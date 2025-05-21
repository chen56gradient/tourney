import asyncio
import json

import yaml
from datasets import load_dataset
from fiber import Keypair

from core.models.payload_models import DpoDatasetColumnsResponse
from core.models.payload_models import TaskType
from core.models.utility_models import Message
from core.models.utility_models import Prompts
from core.models.utility_models import Role
from validator.core.constants import END_OF_REASONING_TAG
from validator.core.constants import MAX_SYNTH_DATA_POINTS
from validator.core.constants import PROMPT_PATH
from validator.core.constants import SYNTH_GEN_BATCH_SIZE
from validator.core.constants import TEXT_SYNTH_MODEL
from validator.core.constants import TEXT_SYNTH_MODEL_MAX_TOKENS
from validator.core.constants import TEXT_SYNTH_MODEL_TEMPERATURE
from validator.core.constants import TEXT_SYNTH_WEAKER_MODEL
from validator.evaluation.utils import get_default_dataset_config
from validator.utils.call_endpoint import post_to_nineteen_chat
from validator.utils.llm import convert_to_nineteen_payload
from validator.utils.llm import extract_json_from_response
from validator.utils.llm import post_to_nineteen_chat_with_reasoning
from validator.utils.logging import get_logger


logger = get_logger(__name__)


def load_prompts() -> Prompts:
    with open(PROMPT_PATH, "r") as file:
        prompts_dict = yaml.safe_load(file)
    return Prompts(**prompts_dict)


def load_and_sample_dataset(dataset_name: str, columns_to_sample: list[str]) -> list[dict]:
    try:
        config_name = get_default_dataset_config(dataset_name)
        dataset = load_dataset(dataset_name, config_name, trust_remote_code=True, streaming=True)
    except Exception as e:
        logger.exception(f"Failed to load dataset {dataset_name}: {e}")
        raise e

    logger.info(f"Loading dataset: {dataset_name}")
    train_dataset = dataset["train"]

    filtered_dataset = train_dataset.remove_columns([col for col in train_dataset.column_names if col not in columns_to_sample])

    num_samples = MAX_SYNTH_DATA_POINTS
    logger.info(f"Taking {num_samples} samples from {dataset_name}")

    sampled_data = filtered_dataset.shuffle(seed=42, buffer_size=1000).take(num_samples)

    sampled_data_list = [sample for sample in sampled_data]
    return sampled_data_list


def create_messages_for_input_generation(
    reformulated_output: str, description: str, output_field: str, schema: dict, prompts: Prompts
) -> list[Message]:
    messages = []
    system_message = Message(role=Role.SYSTEM, content=prompts.input_field_generation_sys)
    messages.append(system_message)
    user_message = Message(
        role=Role.USER,
        content=prompts.input_field_generation_user.format(
            schema=json.dumps(schema), output_field=output_field, output=reformulated_output, description=description
        ),
    )
    messages.append(user_message)
    return messages


def create_messages_for_input_output_reformulation(row: dict, prompts: Prompts) -> list[Message]:
    messages = []
    system_message = Message(role=Role.SYSTEM, content=prompts.input_output_reformulation_sys)
    messages.append(system_message)
    user_message = Message(
        role=Role.USER,
        content=prompts.input_output_reformulation_user.format(data=json.dumps(row)),
    )
    messages.append(user_message)
    return messages


def create_messages_for_input_reformulation(ds_prompt: dict, prompts: Prompts) -> list[Message]:
    prompt_text = next(iter(ds_prompt.values()))

    messages = []
    system_message = Message(role=Role.SYSTEM, content=prompts.input_reformulation_sys)
    messages.append(system_message)
    user_message = Message(
        role=Role.USER,
        content=prompts.input_reformulation_user.format(input=prompt_text))
    messages.append(user_message)
    return messages



def check_the_synthetic_data(synthetic_data_point: dict, original_data_columns: list[str]) -> bool:
    return set(synthetic_data_point.keys()) == set(original_data_columns)


async def generate_paraphrased_version(row: dict, prompts: Prompts, keypair: Keypair) -> dict:
    messages = create_messages_for_input_output_reformulation(row, prompts)
    payload = convert_to_nineteen_payload(messages, TEXT_SYNTH_MODEL, TEXT_SYNTH_MODEL_TEMPERATURE, TEXT_SYNTH_MODEL_MAX_TOKENS)
    result = await post_to_nineteen_chat_with_reasoning(payload, keypair, END_OF_REASONING_TAG)
    paraphrased_data = extract_json_from_response(result) if isinstance(result, str) else result
    return paraphrased_data

async def generate_dpo_reformulation(prompt: str, prompts: Prompts, keypair: Keypair) -> DpoDatasetColumnsResponse:
    messages = create_messages_for_input_reformulation(prompt, prompts)
    payload = convert_to_nineteen_payload(messages, TEXT_SYNTH_MODEL, TEXT_SYNTH_MODEL_TEMPERATURE, TEXT_SYNTH_MODEL_MAX_TOKENS)
    new_prompt = await post_to_nineteen_chat_with_reasoning(payload, keypair, END_OF_REASONING_TAG)
    assert new_prompt, "new prompt should not be None"
    prompt_message = [Message(
        role=Role.USER,
        content=new_prompt)]
    weak_model_payload = convert_to_nineteen_payload(prompt_message, TEXT_SYNTH_WEAKER_MODEL, TEXT_SYNTH_MODEL_TEMPERATURE, TEXT_SYNTH_MODEL_MAX_TOKENS)
    weak_model_result = await post_to_nineteen_chat(weak_model_payload, keypair)
    strong_model_payload = convert_to_nineteen_payload(prompt_message, TEXT_SYNTH_MODEL, TEXT_SYNTH_MODEL_TEMPERATURE, TEXT_SYNTH_MODEL_MAX_TOKENS)
    strong_model_result = await post_to_nineteen_chat_with_reasoning(strong_model_payload, keypair, END_OF_REASONING_TAG)

    return DpoDatasetColumnsResponse(field_prompt = new_prompt, field_chosen=strong_model_result, field_rejected=weak_model_result)


async def process_row(row, prompts, keypair, task_type: TaskType) -> dict | DpoDatasetColumnsResponse:
    if task_type in [TaskType.INSTRUCTTEXTTASK, TaskType.GRPOTASK]:
        try:
            json_synthetic_data_point = await generate_paraphrased_version(row, prompts, keypair)
            
            if not json_synthetic_data_point:
                return None
                
            if check_the_synthetic_data(json_synthetic_data_point, row.keys()):
                return json_synthetic_data_point
            else:
                error_message = (
                    f"Generated data point has incorrect schema. Expected keys: {set(row.keys())}, "
                    f"got: {set(json_synthetic_data_point.keys()) if json_synthetic_data_point else 'None'}"
                )
                logger.error(error_message)
                raise ValueError(error_message)
        except Exception as e:
            logger.error(f"Error processing row: {e}")
            return None
    elif task_type == TaskType.DPOTASK:
        return await generate_dpo_reformulation(row, prompts, keypair)


async def generate_augmented_text_dataset(
    sampled_data: list[dict], keypair: Keypair, task_type: TaskType
    ) -> list[dict] | list[DpoDatasetColumnsResponse]:
    prompts = load_prompts()
    logger.info(f"Creating an augmented dataset with {len(sampled_data)} samples...")
    logger.info(f"Prompts: {prompts}")
    logger.info(f"\nTask type: {task_type}")
    synthetic_dataset = []
    json_errors = 0
    generic_errors = 0
    consecutive_errors = 0
    max_consecutive_errors = 10
    batch_retry_attempts = 2

    total_batches = (len(sampled_data) + SYNTH_GEN_BATCH_SIZE - 1) // SYNTH_GEN_BATCH_SIZE
    for batch_idx in range(0, len(sampled_data), SYNTH_GEN_BATCH_SIZE):
        batch = sampled_data[batch_idx : batch_idx + SYNTH_GEN_BATCH_SIZE]
        current_batch = (batch_idx // SYNTH_GEN_BATCH_SIZE) + 1
        
        batch_success = False
        for retry in range(batch_retry_attempts):
            if retry > 0:
                logger.info(f"Retrying batch {current_batch}/{total_batches} (attempt {retry+1}/{batch_retry_attempts})")
            
            logger.info(f"Processing batch {current_batch}/{total_batches} ({len(batch)} samples)")
            
            tasks = [process_row(row, prompts, keypair, task_type) for row in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            batch_results = []
            batch_error_count = 0
            
            for idx, result in enumerate(results):
                if isinstance(result, Exception):
                    if isinstance(result, json.JSONDecodeError):
                        json_errors += 1
                    else:
                        generic_errors += 1
                    consecutive_errors += 1
                    batch_error_count += 1
                    
                    if consecutive_errors >= max_consecutive_errors:
                        logger.error(f"Maximum consecutive errors reached when generating synthetic data - API service is likely unavailable. Error: {type(result).__name__}: {result}")
                        logger.warning(f"Falling back to dataset splitting instead of generation after {consecutive_errors} failed API calls")
                        return None
                elif result is None:
                    batch_error_count += 1
                else:
                    if batch_idx == 0 and idx < 5:
                        logger.info(f"Sample input: {batch[idx]}")
                        logger.info(f"Sample output: {result}")
                    consecutive_errors = 0
                    batch_results.append(result)
            
            synthetic_dataset.extend(batch_results)
            
            if batch_results:
                logger.info(f"Batch {current_batch}/{total_batches} complete. Generated {len(batch_results)}/{len(batch)} samples successfully")
                if len(batch_results) >= len(batch) * 0.3 or batch_error_count < 3:
                    batch_success = True
                    break
                    
        if not batch_success:
            logger.warning(f"Batch {current_batch} failed to generate any valid synthetic data")
            
    logger.info(f"Finished processing all batches. Generated {len(synthetic_dataset)} samples total. JSON errors: {json_errors}, Other errors: {generic_errors}")
    
    return synthetic_dataset
