"""Local Transformers inference and adapter training for the student."""

import hashlib
import json
import time
from importlib.util import find_spec
from pathlib import Path
from tempfile import TemporaryDirectory

from ..distill import load_distill_dataset
from ..ingest.pipeline import digest
from ..scan.runner import ScanResponse, atomic_json
from ..schemas import ModelResponse
from .openai_compatible import ModelOutputError, schema_message


def dependencies():
    try:
        import torch
        import transformers
    except ImportError:
        raise ValueError('Install cyber-scan[distill] to use a local student model') from None
    return torch, transformers


def file_hash(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def model_fingerprint(base_model):
    if not (base_model / 'config.json').is_file() or not list(base_model.glob('*.safetensors')):
        raise ValueError('Pass a local Transformers checkpoint directory with safetensors weights')
    files = {path.name: file_hash(path) for path in sorted(base_model.iterdir())
             if path.is_file() and path.suffix in {'.json', '.safetensors', '.model', '.jinja', '.txt', '.tiktoken'}}
    return digest(json.dumps(files, sort_keys=True).encode())


def scan_chat(messages, schema):
    # Keep the schema in the leading system message for local chat templates.
    system = {**messages[0], 'content': messages[0]['content'] + '\n\n' + schema_message(schema)['content']}
    return [system, *messages[1:]]


def chat_ids(tokenizer, messages, *, generation_prompt):
    if not tokenizer.chat_template:
        raise ValueError('The local model needs an instruction/chat tokenizer with a chat template')
    return tokenizer.apply_chat_template(messages, tokenize=True, return_dict=False,
                                         add_generation_prompt=generation_prompt)


class LocalStudentClient:
    def __init__(self, config, base_model, adapter=None):
        self.config = config
        base_hash = model_fingerprint(base_model)
        self.identity = {'base_model_sha256': base_hash, 'engine': 'transformers'}
        if adapter is not None:
            manifest = json.loads((adapter / 'training.json').read_text(encoding='utf-8'))
            if manifest.get('version') != 1 or manifest.get('base_model_sha256') != base_hash:
                raise ValueError('Adapter was trained for a different base checkpoint')
            for name in ('adapter_config.json', 'adapter_model.safetensors'):
                if file_hash(adapter / name) != manifest.get('adapter_files', {}).get(name):
                    raise ValueError(f'Adapter failed integrity verification: {name}')
            self.identity['adapter_sha256'] = file_hash(adapter / 'training.json')
            self.identity['training_apk_sha256'] = [dataset['apk_sha256'] for dataset in manifest['datasets']]
            self.identity['training_plan_ids'] = [dataset['plan_id'] for dataset in manifest['datasets']]

        self.torch, hf = dependencies()
        self.device = 'cuda' if self.torch.cuda.is_available() else 'cpu'
        dtype = self.torch.float32
        if self.device == 'cuda':
            dtype = self.torch.bfloat16 if self.torch.cuda.is_bf16_supported() else self.torch.float16
        self.identity.update(dtype=str(dtype), transformers=hf.__version__)
        self.tokenizer = hf.AutoTokenizer.from_pretrained(base_model, local_files_only=True)
        self.model = hf.AutoModelForCausalLM.from_pretrained(
            base_model, local_files_only=True, use_safetensors=True, dtype=dtype,
        ).to(self.device)
        if adapter is not None:
            try:
                from peft import PeftModel
            except ImportError:
                raise ValueError('Install cyber-scan[distill] to load an adapter') from None
            self.model = PeftModel.from_pretrained(self.model, adapter, local_files_only=True)
        self.model.eval()

    def generate(self, messages, response_schema):
        start = time.monotonic()
        ids = chat_ids(self.tokenizer, scan_chat(messages, response_schema),
                       generation_prompt=True)
        max_tokens = self.config.max_output_tokens
        context = getattr(self.model.config, 'max_position_embeddings', None)
        if context and len(ids) + max_tokens > context:
            raise ModelOutputError('Local prompt and output allowance exceed the model context window')
        input_ids = self.torch.tensor([ids], device=self.device)
        pad_id = self.tokenizer.pad_token_id
        if pad_id is None:
            pad_id = self.tokenizer.eos_token_id
        with self.torch.inference_mode():
            output = self.model.generate(input_ids=input_ids, attention_mask=self.torch.ones_like(input_ids),
                                         max_new_tokens=max_tokens, do_sample=False, pad_token_id=pad_id)
        completion = output[0, len(ids):].tolist()
        eos = self.model.generation_config.eos_token_id
        eos_ids = eos if isinstance(eos, list) else [eos]
        finished = bool(completion) and completion[-1] in eos_ids
        return ModelResponse(
            model=self.config.model, text=self.tokenizer.decode(completion, skip_special_tokens=True),
            finish_reason='stop' if finished else 'length',
            usage={'prompt_tokens': len(ids), 'completion_tokens': len(completion),
                   'total_tokens': len(ids) + len(completion)},
            latency_seconds=time.monotonic() - start, attempts=1,
        )


def train_adapter(base_model, datasets, output, *, epochs=1, max_length=8192,
                  qlora=False, allow_unreviewed=False):
    if output.exists():
        raise ValueError('Adapter output already exists')
    if epochs <= 0 or max_length <= 0:
        raise ValueError('Epochs and max length must be positive')
    corpus = [load_distill_dataset(path, allow_unreviewed=allow_unreviewed) for path in datasets]
    torch, hf = dependencies()
    try:
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    except ImportError:
        raise ValueError('Install cyber-scan[distill] to train an adapter') from None

    cuda = torch.cuda.is_available()
    if qlora and not cuda:
        raise ValueError('QLoRA requires CUDA; use standard LoRA for a CPU smoke test')
    if qlora and find_spec('bitsandbytes') is None:
        raise ValueError('Install cyber-scan[qlora] to use 4-bit adapter training')
    dtype = torch.bfloat16 if cuda and torch.cuda.is_bf16_supported() else torch.float32
    kwargs = {'local_files_only': True, 'use_safetensors': True, 'dtype': dtype}
    if qlora:
        kwargs.update(
            device_map={'': 0},
            quantization_config=hf.BitsAndBytesConfig(
                load_in_4bit=True, bnb_4bit_quant_type='nf4', bnb_4bit_use_double_quant=True,
                bnb_4bit_compute_dtype=dtype,
            ),
        )
    base_hash = model_fingerprint(base_model)
    tokenizer = hf.AutoTokenizer.from_pretrained(base_model, local_files_only=True)
    model_config = hf.AutoConfig.from_pretrained(base_model, local_files_only=True)
    context = getattr(model_config, 'max_position_embeddings', None)
    limit = min(max_length, context) if context else max_length
    schema = ScanResponse.model_json_schema()
    examples = []
    seen = set()
    for manifest, rows in corpus:
        for row in rows:
            key = (manifest['plan_id'], row['unit_id'])
            if key in seen:
                raise ValueError(f'Duplicate training example: {row["unit_id"]}')
            seen.add(key)
            messages = scan_chat(row['messages'], schema)
            answer = ScanResponse.model_validate(row['completion']).model_dump_json()
            prompt = chat_ids(tokenizer, messages, generation_prompt=True)
            prefix = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            rendered = tokenizer.apply_chat_template(
                [*messages, {'role': 'assistant', 'content': answer}], tokenize=False,
            )
            if not rendered.startswith(prefix) or len(rendered) <= len(prefix):
                raise ValueError('Chat template does not preserve the assistant response boundary')
            # Tokenize the suffix separately so a BPE merge cannot consume the prompt boundary.
            target = tokenizer(rendered[len(prefix):], add_special_tokens=False).input_ids
            full = prompt + target
            if len(full) > limit:
                raise ValueError(f'Training example {row["unit_id"]} is {len(full)} tokens, above {limit}')
            # Apply loss only to the assistant completion, including the turn terminator.
            examples.append({'input_ids': full, 'attention_mask': [1] * len(full),
                             'labels': [-100] * len(prompt) + full[len(prompt):]})

    hf.set_seed(42)
    model = hf.AutoModelForCausalLM.from_pretrained(base_model, **kwargs)
    if qlora:
        model = prepare_model_for_kbit_training(model)
    model.config.use_cache = False
    model = get_peft_model(model, LoraConfig(task_type='CAUSAL_LM', target_modules='all-linear',
                                           r=8, lora_alpha=16, lora_dropout=0.05))
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix='adapter-', dir=output.parent) as staging:
        staging = Path(staging)
        args = hf.TrainingArguments(
            output_dir=str(staging), num_train_epochs=epochs, per_device_train_batch_size=1,
            gradient_accumulation_steps=4, learning_rate=2e-4, save_strategy='no',
            report_to='none', use_cpu=not cuda, bf16=dtype == torch.bfloat16, seed=42,
        )
        trainer = hf.Trainer(model=model, args=args, train_dataset=examples,
                             data_collator=hf.default_data_collator)
        result = trainer.train()
        model.save_pretrained(staging, safe_serialization=True)
        manifest = {
            'version': 1, 'base_model_sha256': base_hash,
            'method': 'qlora' if qlora else 'lora',
            'datasets': [item for item, _ in corpus], 'examples': len(examples),
            'epochs': epochs, 'max_length': limit, 'seed': 42, 'steps': result.global_step,
            'adapter_files': {name: file_hash(staging / name)
                              for name in ('adapter_config.json', 'adapter_model.safetensors')},
        }
        output.mkdir()
        for name in manifest['adapter_files']:
            (staging / name).replace(output / name)
        atomic_json(output / 'training.json', manifest)
    return manifest
