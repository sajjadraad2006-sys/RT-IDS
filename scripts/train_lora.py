"""Fine-tune CyberGuard Defense LLM using QLoRA and PEFT.

Runs parameter-efficient fine-tuning on Foundation-Sec-8B or Llama-3-8B-Instruct
using the grounded defense dataset produced by export_defense_finetuning_dataset.py.
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_lora")


def train_defense_lora(
    dataset_path: str,
    base_model: str = "Foundation-Sec-8B-Instruct",
    output_dir: str = "data/models/defense_lora",
    epochs: int = 3,
    batch_size: int = 4,
    learning_rate: float = 2e-4,
    lora_r: int = 16,
    lora_alpha: int = 32,
):
    """Fine-tuning harness using HuggingFace TRL, PEFT, and BitsAndBytes."""
    logger.info("Initializing LoRA fine-tuning for model: %s", base_model)
    logger.info("Dataset: %s | Epochs: %d | Batch size: %d", dataset_path, epochs, batch_size)

    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from datasets import load_dataset
        from trl import SFTTrainer
    except ImportError as e:
        logger.error(
            "Training dependencies missing: %s. "
            "To train, install: pip install torch transformers peft trl bitsandbytes datasets accelerate",
            e,
        )
        return False

    # Check CUDA availability
    device_map = "auto" if torch.cuda.is_available() else "cpu"
    logger.info("Target compute device: %s", device_map)

    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Load quantized model if CUDA available
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
        device_map=device_map,
        trust_remote_code=True,
    )

    # Configure LoRA adapter
    lora_config = LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        target_modules=["q_proj", "v_proj", "k_proj", "o_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )

    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # Load dataset
    dataset = load_dataset("json", data_files=dataset_path, split="train")

    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=2,
        learning_rate=learning_rate,
        logging_steps=10,
        save_strategy="epoch",
        fp16=torch.cuda.is_available(),
    )

    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        args=training_args,
        peft_config=lora_config,
    )

    logger.info("Starting training loop...")
    trainer.train()

    # Save final LoRA adapter
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(output_path))
    tokenizer.save_pretrained(str(output_path))
    logger.info("LoRA fine-tuning completed! Adapter saved to: %s", output_path)
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberGuard Defense LoRA Trainer")
    parser.add_argument("--dataset", type=str, default="data/defense_finetuning_dataset.jsonl")
    parser.add_argument("--model", type=str, default="Foundation-Sec-8B-Instruct")
    parser.add_argument("--output", type=str, default="data/models/defense_lora")
    parser.add_argument("--epochs", type=int, default=3)
    args = parser.parse_args()

    train_defense_lora(
        dataset_path=args.dataset,
        base_model=args.model,
        output_dir=args.output,
        epochs=args.epochs,
    )
