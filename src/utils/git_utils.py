import os
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path

class GitService:
    def __init__(self, repo_url: str, local_path: str):
        self.repo_url = repo_url
        self.local_path = Path(local_path).absolute()
        self._ensure_repo()

    def _ensure_repo(self):
        """저장소가 없으면 클론하고, 있으면 업데이트를 가져옵니다."""
        if not self.local_path.exists():
            print(f"Cloning {self.repo_url} to {self.local_path}...")
            self.local_path.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "clone", self.repo_url, str(self.local_path)], check=True)
        else:
            print(f"Fetching updates for {self.local_path}...")
            subprocess.run(["git", "-C", str(self.local_path), "fetch", "origin"], check=True)

    def run_command(self, args: List[str]) -> str:
        """로컬 저장소에서 git 명령을 실행하고 출력을 반환합니다."""
        cmd = ["git", "-C", str(self.local_path)] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout or ""
        except subprocess.CalledProcessError as e:
            print(f"  [GIT ERROR] 명령 {args} 실패: {e.stderr}")
            raise e

    def get_show_output(self, commit_sha: str, file_path: str) -> str:
        """특정 커밋의 특정 파일에 대해 `git show -m -U0`를 실행합니다."""
        # -m은 머지 커밋에 대해 각 부모와의 diff를 보여줍니다.
        # -- 는 특정 파일 경로를 지정합니다.
        return self.run_command(["show", "-m", "-U0", commit_sha, "--", file_path])

    def get_file_content(self, commit_ref: str, file_path: str) -> str:
        """특정 커밋/참조에서의 전체 파일 내용을 가져옵니다."""
        # raw 내용을 가져오기 위해 SHA:PATH 구문을 사용하는 것이 올바릅니다.
        return self.run_command(["show", f"{commit_ref}:{file_path}"])

    def get_modified_files_info(self, commit_sha: str) -> List[Dict[str, Any]]:
        """`git show --numstat`를 사용하여 커밋에서 수정된 파일 정보를 가져옵니다."""
        # 머지 커밋에서도 수정된 파일을 확인하기 위해 -m이 필요합니다.
        output = self.run_command(["show", "-m", "--numstat", "--format=", commit_sha])
        files = {}
        for line in output.splitlines():
            if line.strip() and '\t' in line:
                added, deleted, path = line.split('\t')
                try:
                    changes = (int(added) if added != '-' else 0) + (int(deleted) if deleted != '-' else 0)
                except ValueError: 
                    changes = 0
                
                # 여러 부모가 동일한 파일에 대한 변경사항을 보여주는 경우 최대 변경 횟수를 선택합니다.
                if path not in files or changes > files[path]:
                    files[path] = changes
                    
        return [{"path": p, "changes": c} for p, c in files.items()]
