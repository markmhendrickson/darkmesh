from typing import Dict

ALLOWED_TEMPLATES = {"warm_intro_v1"}


class PolicyError(ValueError):
    pass


def validate_template(template: str) -> None:
    if template not in ALLOWED_TEMPLATES:
        raise PolicyError(f"Template not allowed: {template}")


def validate_constraints(constraints: Dict) -> Dict:
    max_candidates = int(constraints.get("max_candidates", 3))
    min_strength = float(constraints.get("min_strength", 0.5))

    if max_candidates < 1 or max_candidates > 10:
        raise PolicyError("max_candidates must be between 1 and 10")
    if min_strength < 0.0 or min_strength > 1.0:
        raise PolicyError("min_strength must be between 0 and 1")

    return {
        "max_candidates": max_candidates,
        "min_strength": min_strength,
    }


def match_target(contact: Dict, target: Dict) -> bool:
    company = (contact.get("org") or "").lower()
    role = (contact.get("role") or "").lower()
    target_company = (target.get("company") or "").lower()
    target_role = (target.get("role") or "").lower()

    company_ok = target_company in company if target_company else True
    role_ok = target_role in role if target_role else True

    return company_ok and role_ok

