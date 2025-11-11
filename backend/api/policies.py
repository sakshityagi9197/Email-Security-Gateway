from __future__ import annotations

import os
import shutil
import time
import uuid
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
import yaml

from backend.api.auth import require_roles


POLICY_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "policy_attachment"))
ACTIVE_META = os.path.join(POLICY_DIR, ".active_policy.json")

router = APIRouter(tags=["policies"])

def _list_policy_files() -> List[str]:
    """List all YAML policy files in the policy directory"""
    if not os.path.isdir(POLICY_DIR):
        return []
    return [f for f in os.listdir(POLICY_DIR) if f.endswith(".yaml")]

def _policy_id_from_filename(fn: str) -> str:
    """Extract policy ID from filename"""
    base = os.path.splitext(fn)[0]
    return base

def get_active_policy_path() -> Optional[str]:
    """Get the path of the currently active policy file"""
    policy = _get_active_policy()
    return policy["path"] if policy else None

def _get_active_policy() -> Optional[Dict[str, Any]]:
    """Get active policy information including ID and path"""
    try:
        if os.path.exists(ACTIVE_META):
            with open(ACTIVE_META, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data and isinstance(data, dict):
                policy_id = data.get("id")
                if policy_id:
                    policy_path = os.path.join(POLICY_DIR, f"{policy_id}.yaml")
                    if os.path.exists(policy_path):
                        return {
                            "id": policy_id,
                            "path": policy_path,
                            "activated_at": data.get("activated_at")
                        }
    except Exception:
        pass
    return None

def _get_active_id() -> Optional[str]:
    """Get just the active policy ID"""
    policy = _get_active_policy()
    return policy["id"] if policy else None


def _is_active(path: str) -> bool:
    """Return True if the given policy file is currently active"""
    try:
        active_policy = _get_active_policy()
        if active_policy and os.path.exists(path):
            return os.path.samefile(path, active_policy["path"])
    except Exception:
        pass
    return False


@router.get("/policies")
def policies_list(limit: int = Query(5, ge=1, le=100), _=Depends(require_roles("viewer","analyst","admin"))) -> Dict[str, Any]:
    files = _list_policy_files()
    # sort by mtime desc
    files.sort(key=lambda f: os.path.getmtime(os.path.join(POLICY_DIR, f)), reverse=True)
    active_id = _get_active_id()
    out = []
    for f in files[:limit]:
        p = os.path.join(POLICY_DIR, f)
        pid = _policy_id_from_filename(f)
        out.append({
            "id": pid,
            "name": f,
            "status": "active" if (active_id and pid == active_id) or _is_active(p) else "inactive",
            "last_modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(p))),
        })
    return {"items": out}


@router.get("/policy/{policy_id}")
def policy_get(policy_id: str, _=Depends(require_roles("viewer","analyst","admin"))) -> Dict[str, Any]:
    path = os.path.join(POLICY_DIR, f"{policy_id}.yaml")
    if not os.path.exists(path):
        raise HTTPException(404, detail="Not found")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    # Best-effort parse to structured JSON
    parsed = None
    try:
        import yaml  # type: ignore
        parsed = yaml.safe_load(content)
    except Exception:
        parsed = None
    active_id = _get_active_id()
    return {
        "id": policy_id,
        "name": os.path.basename(path),
        "active": (active_id == policy_id) or _is_active(path),
        "content": content,
        "parsed": parsed,
    }


class PolicyCreate(BaseModel):
    name: str
    content: str

    @classmethod
    def validate_yaml_content(cls, content: str) -> None:
        """Validate that the content is valid YAML and has the expected structure"""
        try:
            import yaml
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                raise ValueError("Root YAML must be a dictionary")
            
            policy = data.get("policy")
            if not policy:
                raise ValueError("'policy' section is required")
            if not isinstance(policy, dict):
                raise ValueError("'policy' must be a dictionary")
            
            # Validate policy fields
            if not policy.get("name"):
                raise ValueError("Policy name is required")
            if not policy.get("version"):
                raise ValueError("Policy version is required")
            
            rules = data.get("rules")
            if rules is None:
                raise ValueError("'rules' section is required")
            if not isinstance(rules, list):
                raise ValueError("'rules' must be a list")
                
            for i, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    raise ValueError(f"Rule {i+1} must be a dictionary")
                if not rule.get("id"):
                    raise ValueError(f"Rule {i+1} must have an 'id'")
                if not rule.get("name"):
                    raise ValueError(f"Rule {i+1} must have a 'name'")
                if not rule.get("action"):
                    raise ValueError(f"Rule {i+1} must have an 'action'")
                if not rule.get("category"):
                    raise ValueError(f"Rule {i+1} must have a 'category'")
                if "conditions" not in rule:
                    rule["conditions"] = {}  # Default to empty conditions if not specified
                
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML format: {str(e)}")
        except Exception as e:
            raise ValueError(f"Invalid policy format: {str(e)}")


@router.post("/policy")
def policy_create(body: PolicyCreate, _=Depends(require_roles("admin"))) -> Dict[str, Any]:
    try:
        # Validate YAML content
        PolicyCreate.validate_yaml_content(body.content)
        
        # Create directory if needed
        os.makedirs(POLICY_DIR, exist_ok=True)
        
        # Generate or clean policy ID
        pid = (body.name or uuid.uuid4().hex).strip().replace(" ", "_")
        path = os.path.join(POLICY_DIR, f"{pid}.yaml")
        
        # Check for existing policy
        if os.path.exists(path):
            raise HTTPException(400, detail="Policy with same id already exists")
            
        # Write the policy file
        with open(path, "w", encoding="utf-8") as f:
            f.write(body.content)
            
        return {
            "id": pid,
            "name": os.path.basename(path),
            "message": "Policy created successfully"
        }
    except ValueError as e:
        raise HTTPException(422, detail=str(e))
    except Exception as e:
        raise HTTPException(500, detail=f"Failed to create policy: {str(e)}")


@router.put("/policy/{policy_id}")
def policy_update(policy_id: str, body: PolicyCreate, _=Depends(require_roles("admin"))) -> Dict[str, Any]:
    try:
        # Validate policy ID
        if ".." in policy_id or "/" in policy_id or "\\" in policy_id:
            raise HTTPException(400, detail="Invalid policy ID")
            
        # Validate YAML content
        PolicyCreate.validate_yaml_content(body.content)
        
        # Get policy path
        path = os.path.join(POLICY_DIR, f"{policy_id}.yaml")
        if not os.path.exists(path):
            raise HTTPException(404, detail="Policy not found")
            
        # Create backup
        backup_path = f"{path}.bak"
        try:
            shutil.copy2(path, backup_path)
        except Exception as e:
            print(f"Warning: Failed to create backup: {e}")
            
        try:
            # Write new content
            with open(path, "w", encoding="utf-8") as f:
                f.write(body.content)
                
            # Remove backup if successful
            if os.path.exists(backup_path):
                os.remove(backup_path)
                
            return {
                "id": policy_id,
                "name": os.path.basename(path),
                "message": "Policy updated successfully"
            }
        except Exception as e:
            # Restore from backup if write failed
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, path)
                os.remove(backup_path)
            raise e
            
    except ValueError as e:
        raise HTTPException(422, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=f"Failed to update policy: {str(e)}")


@router.patch("/policy/{policy_id}/activate")
def policy_activate(policy_id: str, _=Depends(require_roles("admin"))) -> Dict[str, Any]:
    """Activate a policy by marking it as active in metadata"""
    policy_path = os.path.join(POLICY_DIR, f"{policy_id}.yaml")
    if not os.path.exists(policy_path):
        raise HTTPException(404, detail="Policy file not found")
    
    # Check if policy is already active
    active_policy = _get_active_policy()
    if active_policy and active_policy["id"] == policy_id:
        return {
            "id": policy_id,
            "active": True,
            "message": "Policy is already active"
        }
        
    try:
        # Validate that the policy file is readable
        with open(policy_path, "r", encoding="utf-8") as f:
            yaml.safe_load(f)  # Validate YAML syntax
            
        # Update metadata to mark this policy as active
        with open(ACTIVE_META, "w", encoding="utf-8") as f:
            json.dump({
                "id": policy_id,
                "path": policy_path,
                "activated_at": int(time.time())
            }, f, indent=2)
            
        return {
            "id": policy_id, 
            "active": True,
            "message": "Policy activated successfully"
        }
    except yaml.YAMLError as e:
        raise HTTPException(422, detail=f"Invalid policy YAML: {str(e)}")
    except Exception as e:
        raise HTTPException(500, detail=f"Failed to activate policy: {str(e)}")


@router.delete("/policy/{policy_id}")
def policy_delete(policy_id: str, _=Depends(require_roles("admin"))) -> Dict[str, Any]:
    path = os.path.join(POLICY_DIR, f"{policy_id}.yaml")
    # Avoid deleting the active file alias
    if not os.path.exists(path):
        raise HTTPException(404, detail="Not found")
    try:
        os.remove(path)
        return {"deleted": policy_id}
    except Exception:
        raise HTTPException(500, detail="Failed to delete")
