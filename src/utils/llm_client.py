"""
LLM Client - OpenAI 전용 간소화 버전
"""
import os
import json
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()


def parse_kv_string_to_dict(kv_string: Optional[str]) -> Dict[str, Any]:
    """
    Key-Value 문자열을 딕셔너리로 변환
    예: "temperature=0.2;max_tokens=1024" -> {"temperature": 0.2, "max_tokens": 1024}
    """
    if not kv_string:
        return {}
    
    result = {}
    for pair in kv_string.split(";"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            key = key.strip()
            value = value.strip()
            
            # 타입 변환 시도
            if value.lower() == "true":
                result[key] = True
            elif value.lower() == "false":
                result[key] = False
            else:
                try:
                    result[key] = int(value)
                except ValueError:
                    try:
                        result[key] = float(value)
                    except ValueError:
                        result[key] = value
    return result


def generate_simple_prompt(user_message: str) -> List[Dict[str, str]]:
    """
    간단한 프롬프트 생성 (OpenAI 메시지 형식)
    """
    return [{"role": "user", "content": user_message}]


def extract_LLM_response_by_prefix(response: str, prefix: str) -> str:
    """
    LLM 응답에서 특정 prefix 이후의 텍스트를 추출
    """
    if prefix in response:
        return response.split(prefix, 1)[1].strip()
    return response.strip()


class BaseLLMClient:
    """
    Base LLM Client 추상 클래스
    """
    def __init__(self, model_name: str):
        self.model_name = model_name
    
    def generate_text(self, messages: List[Dict[str, str]], settings: Optional[Dict[str, Any]] = None) -> str:
        """
        텍스트 생성 메서드 (하위 클래스에서 구현)
        """
        raise NotImplementedError("Subclasses must implement generate_text method")


class OpenAIClient(BaseLLMClient):
    """OpenAI API 클라이언트"""
    
    def __init__(self, model_name: str = "gpt-4o-mini"):      # 모델 기본값
        super().__init__(model_name)
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "OPENAI_API_KEY not found in environment variables.\n"
                "Please create a .env file with: OPENAI_API_KEY=your_key_here"
            )
        
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=self.api_key)
        except ImportError:
            raise ImportError(
                "openai package not installed.\n"
                "Run: pip install openai"
            )
    
    def generate_text(self, messages: List[Dict[str, str]], settings: Optional[Dict[str, Any]] = None) -> str:
        """OpenAI API 호출"""
        if settings is None:
            settings = {}
        
        # 기본 설정
        default_settings = {
            "temperature": 0.2,            # 창의성
            "max_tokens": 16384,           # 최대 토큰 수 
        }
        default_settings.update(settings)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                **default_settings
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"OpenAI API call failed: {str(e)}")


class DummyClient(BaseLLMClient):
    """
    테스트용 Dummy 클라이언트
    스키마 검증용 llm 응답과 똑같은 형식의 응답을 반환
    llm 호출 x
    """
    def __init__(self, model_name: str = "dummy"):
        super().__init__(model_name)
    
    def generate_text(self, messages: List[Dict[str, str]], settings: Optional[Dict[str, Any]] = None) -> str:
        """테스트용 더미 응답"""
        return json.dumps({
            "purpose": "To fix a vulnerability in the code.",
            "function": "1. Parse input\n2. Validate data\n3. Process request",
            "analysis": "The code lacks proper validation.",
            "vulnerability_behavior": {
                "vulnerability_cause_description": "Missing input validation.",
                "trigger_condition": "Malicious user input.",
                "specific_code_behavior_causing_vulnerability": "Direct use of user input without sanitization."
            },
            "solution": "Add input validation and sanitization."
        })


def get_llm_client(model_name: str) -> BaseLLMClient:
    """
    모델 이름에 따라 적절한 LLM 클라이언트를 반환
    
    지원 모델:
    - gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-3.5-turbo -> OpenAI
    - dummy -> DummyClient (테스트용, API 키 불필요)
    
    Examples:
        >>> client = get_llm_client("gpt-4o-mini")
        >>> client = get_llm_client("dummy")  # 테스트용
    """
    model_lower = model_name.lower()
    
    if "dummy" in model_lower:
        return DummyClient(model_name)
    elif "gpt" in model_lower:
        return OpenAIClient(model_name)
    else:
        # 기본값: OpenAI로 시도
        return OpenAIClient(model_name)


if __name__ == "__main__":
    # 간단한 테스트
    print("=" * 60)
    print("Testing LLM Client (OpenAI Only)")
    print("=" * 60)
    
    # Dummy 클라이언트 테스트 (API 키 불필요)
    print("\n[1] Testing Dummy Client...")
    try:
        client = get_llm_client("dummy")
        messages = generate_simple_prompt("Test prompt")
        response = client.generate_text(messages)
        print(f"✓ Dummy Client works!")
        print(f"  Response: {response[:100]}...")
    except Exception as e:
        print(f"✗ Error: {e}")
    
    # OpenAI 클라이언트 테스트
    print("\n[2] Testing OpenAI Client...")
    try:
        client = get_llm_client("gpt-4o-mini")
        print(f"✓ OpenAI Client initialized: {client.model_name}")
        print(f"  API Key: {client.api_key[:10]}..." if client.api_key else "  API Key: Not found")
    except ValueError as e:
        print(f"✗ {e}")
    except ImportError as e:
        print(f"✗ {e}")