# core/brain.py
# DRAKBEN v2.0 - AI Brain with 5 Core Modules
# Real LLM Integration

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import json
import re

# LLM Client import
try:
    from llm.openrouter_client import OpenRouterClient
    LLM_AVAILABLE = True
except ImportError:
    OpenRouterClient = None
    LLM_AVAILABLE = False


@dataclass
class ExecutionContext:
    """Execution context for tracking state"""
    target: Optional[str] = None
    language: str = "tr"
    system_info: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict] = field(default_factory=list)
    current_step: int = 0
    total_steps: int = 0
    errors_encountered: List[Dict] = field(default_factory=list)


# MODULE 1: Master Orchestrator
class MasterOrchestrator:
    """
    Ana orkestratör - Tüm modülleri koordine eder
    """
    
    def __init__(self):
        self.context = ExecutionContext()
        self.reasoning_engine = None
        self.context_manager = None
        self.self_correction = None
        self.decision_engine = None
    
    def initialize(self, reasoning, context_mgr, self_corr, decision):
        """Initialize sub-modules"""
        self.reasoning_engine = reasoning
        self.context_manager = context_mgr
        self.self_correction = self_corr
        self.decision_engine = decision
    
    def process_request(self, user_input: str, system_context: Dict) -> Dict:
        """
        Ana işlem döngüsü
        
        Returns:
            {
                "plan": [...],
                "needs_approval": bool,
                "reasoning": str,
                "next_action": {...}
            }
        """
        # Update context
        self.context_manager.update(system_context)
        
        # Continuous reasoning
        analysis = self.reasoning_engine.analyze(user_input, self.context)
        
        # Decision making
        decision = self.decision_engine.decide(analysis, self.context)
        
        # Self-correction check
        if decision.get("has_risks"):
            corrected = self.self_correction.review(decision)
            decision = corrected
        
        return decision
    
    def execute_plan(self, plan: List[Dict]) -> List[Dict]:
        """Execute a multi-step plan"""
        results = []
        self.context.total_steps = len(plan)
        
        for i, step in enumerate(plan):
            self.context.current_step = i + 1
            
            # Add to history
            self.context.history.append({
                "step": i + 1,
                "action": step,
                "status": "executing"
            })
            
            results.append(step)
        
        return results


# MODULE 2: Continuous Reasoning
class ContinuousReasoning:
    """
    Sürekli düşünme motoru - Her adımda yeniden değerlendirir
    Gerçek LLM entegrasyonu ile
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.reasoning_history = []
        self.use_llm = llm_client is not None
    
    def analyze(self, user_input: str, context: ExecutionContext) -> Dict:
        """
        Kullanıcı girdisini analiz et ve plan oluştur
        LLM varsa AI-powered, yoksa rule-based
        
        Returns:
            {
                "intent": str,
                "confidence": float,
                "steps": List[Dict],
                "reasoning": str,
                "risks": List[str],
                "llm_response": str (optional)
            }
        """
        # Try LLM-powered analysis first
        if self.use_llm and self.llm_client:
            llm_analysis = self._analyze_with_llm(user_input, context)
            if llm_analysis.get("success"):
                return llm_analysis
        
        # Fallback to rule-based analysis
        return self._analyze_rule_based(user_input, context)
    
    def _analyze_with_llm(self, user_input: str, context: ExecutionContext) -> Dict:
        """LLM-powered analysis"""
        system_prompt = """You are DRAKBEN, an AI penetration testing assistant.
Analyze the user's request and respond in JSON format:
{
    "intent": "scan|find_vulnerability|exploit|get_shell|generate_payload|chat",
    "confidence": 0.0-1.0,
    "steps": [{"action": "step_name", "tool": "tool_name", "description": "what to do"}],
    "reasoning": "explanation in Turkish",
    "risks": ["risk1", "risk2"],
    "command": "suggested shell command if applicable"
}

Available tools: nmap, sqlmap, nikto, gobuster, hydra, msfconsole, msfvenom, netcat
Target: """ + (context.target or "Not set")
        
        try:
            response = self.llm_client.query(user_input, system_prompt)
            
            # Check for error responses
            if response.startswith("[") and any(x in response for x in ["Error", "Offline", "Timeout"]):
                return {"success": False, "error": response}
            
            # Try to parse JSON from response
            parsed = self._parse_llm_response(response)
            if parsed:
                parsed["success"] = True
                parsed["llm_response"] = response
                self.reasoning_history.append(parsed)
                return parsed
            
            # If not JSON, use as chat response
            return {
                "success": True,
                "intent": "chat",
                "confidence": 0.9,
                "steps": [{"action": "respond", "type": "chat"}],
                "reasoning": response,
                "risks": [],
                "llm_response": response
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_llm_response(self, response: str) -> Optional[Dict]:
        """Parse JSON from LLM response"""
        try:
            # Try direct JSON parse
            return json.loads(response)
        except json.JSONDecodeError:
            pass
        
        # Try to extract JSON from text
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        
        return None
    
    def _analyze_rule_based(self, user_input: str, context: ExecutionContext) -> Dict:
        """Rule-based analysis (fallback when LLM unavailable)"""
        # Intent detection
        intent = self._detect_intent(user_input)
        
        # Risk assessment
        risks = self._assess_risks(intent, context)
        
        # Step planning
        steps = self._plan_steps(intent, context)
        
        # Reasoning explanation
        reasoning = self._generate_reasoning(intent, steps, risks)
        
        analysis = {
            "intent": intent,
            "confidence": 0.85,
            "steps": steps,
            "reasoning": reasoning,
            "risks": risks,
            "success": True
        }
        
        self.reasoning_history.append(analysis)
        return analysis
    
    def _detect_intent(self, user_input: str) -> str:
        """Detect user intent from input"""
        user_lower = user_input.lower()
        
        # Pentest intents
        if any(word in user_lower for word in ["tara", "scan", "port", "keşif"]):
            return "scan"
        elif any(word in user_lower for word in ["açık", "zafiyet", "vuln", "cve"]):
            return "find_vulnerability"
        elif any(word in user_lower for word in ["exploit", "istismar", "saldır"]):
            return "exploit"
        elif any(word in user_lower for word in ["shell", "kabuk", "reverse"]):
            return "get_shell"
        elif any(word in user_lower for word in ["payload", "yük"]):
            return "generate_payload"
        else:
            return "chat"
    
    def _assess_risks(self, intent: str, context: ExecutionContext) -> List[str]:
        """Assess risks for the intent"""
        risks = []
        
        if intent in ["exploit", "get_shell"]:
            risks.append("Potentially destructive operation")
            risks.append("Requires authorization")
        
        if not context.system_info.get("is_root"):
            if intent in ["scan", "exploit"]:
                risks.append("May need elevated privileges")
        
        return risks
    
    def _plan_steps(self, intent: str, context: ExecutionContext) -> List[Dict]:
        """Plan execution steps based on intent"""
        steps = []
        
        if intent == "scan":
            steps = [
                {"action": "check_tools", "tool": "nmap"},
                {"action": "port_scan", "tool": "nmap"},
                {"action": "service_detection", "tool": "nmap"},
                {"action": "analyze_results"}
            ]
        
        elif intent == "find_vulnerability":
            steps = [
                {"action": "scan", "tool": "nmap"},
                {"action": "web_scan", "tool": "nikto"},
                {"action": "vuln_scan", "tool": "nmap_scripts"},
                {"action": "analyze_vulns"}
            ]
        
        elif intent == "get_shell":
            steps = [
                {"action": "scan_target"},
                {"action": "find_vulnerabilities"},
                {"action": "select_exploit"},
                {"action": "generate_payload"},
                {"action": "execute_exploit"},
                {"action": "verify_shell"}
            ]
        
        elif intent == "generate_payload":
            steps = [
                {"action": "determine_target_os"},
                {"action": "generate_payloads"},
                {"action": "encode_if_needed"}
            ]
        
        else:  # chat
            steps = [{"action": "respond", "type": "chat"}]
        
        return steps
    
    def _generate_reasoning(self, intent: str, steps: List[Dict], risks: List[str]) -> str:
        """Generate human-readable reasoning"""
        if intent == "scan":
            return f"Port taraması yapılacak. {len(steps)} adım planlandı."
        elif intent == "find_vulnerability":
            return f"Zafiyet taraması yapılacak. Önce port taraması, sonra servis analizi."
        elif intent == "get_shell":
            return f"Shell erişimi için {len(steps)} adımlı plan. {'Riskli işlem!' if risks else ''}"
        else:
            return "Kullanıcı ile sohbet modu."
    
    def re_evaluate(self, execution_result: Dict, context: ExecutionContext) -> Dict:
        """
        Bir adım sonrasında yeniden değerlendir
        """
        # Check if we need to adjust the plan
        if not execution_result.get("success"):
            # Plan adjustment needed
            return {
                "action": "adjust_plan",
                "reason": execution_result.get("error"),
                "new_steps": self._generate_recovery_steps(execution_result)
            }
        
        return {"action": "continue"}
    
    def _generate_recovery_steps(self, failed_result: Dict) -> List[Dict]:
        """Generate recovery steps when something fails"""
        error = failed_result.get("error", "")
        
        if "command not found" in error.lower():
            return [
                {"action": "install_tool", "tool": failed_result.get("tool")},
                {"action": "retry", "previous": failed_result}
            ]
        elif "permission denied" in error.lower():
            return [
                {"action": "escalate_privileges"},
                {"action": "retry", "previous": failed_result}
            ]
        else:
            return [{"action": "try_alternative_method"}]


# MODULE 3: Context Manager
class ContextManager:
    """
    Bağlam yöneticisi - Sistem durumunu takip eder
    """
    
    def __init__(self):
        self.current_context = {}
        self.context_history = []
    
    def update(self, new_context: Dict):
        """Update current context"""
        self.context_history.append(self.current_context.copy())
        self.current_context.update(new_context)
    
    def get(self, key: str, default=None):
        """Get context value"""
        return self.current_context.get(key, default)
    
    def get_full_context(self) -> Dict:
        """Get complete context for AI"""
        return {
            "current": self.current_context,
            "previous": self.context_history[-1] if self.context_history else {},
            "changes": self._detect_changes()
        }
    
    def _detect_changes(self) -> List[str]:
        """Detect what changed in context"""
        changes = []
        
        if not self.context_history:
            return ["Initial context"]
        
        prev = self.context_history[-1]
        curr = self.current_context
        
        for key in curr:
            if key not in prev:
                changes.append(f"Added: {key}")
            elif curr[key] != prev.get(key):
                changes.append(f"Changed: {key}")
        
        return changes
    
    def clear_history(self):
        """Clear context history"""
        self.context_history = []


# MODULE 4: Self Correction
class SelfCorrection:
    """
    Kendi kendine düzeltme - Hataları tespit edip düzeltir
    """
    
    def __init__(self):
        self.correction_history = []
    
    def review(self, decision: Dict) -> Dict:
        """
        Review a decision and correct if needed
        
        Args:
            decision: Decision to review
            
        Returns:
            Corrected decision
        """
        corrected = decision.copy()
        corrections = []
        
        # Check for dangerous commands
        if self._is_dangerous(decision):
            corrections.append("Added safety check")
            corrected["needs_approval"] = True
            corrected["safety_warning"] = "Potentially destructive operation"
        
        # Check for missing prerequisites
        prereqs = self._check_prerequisites(decision)
        if prereqs:
            corrections.append(f"Added prerequisites: {', '.join(prereqs)}")
            corrected["prerequisites"] = prereqs
        
        # Check for optimization opportunities
        optimizations = self._suggest_optimizations(decision)
        if optimizations:
            corrections.append(f"Suggested optimizations")
            corrected["optimizations"] = optimizations
        
        if corrections:
            corrected["corrected"] = True
            corrected["corrections"] = corrections
            self.correction_history.append({
                "original": decision,
                "corrected": corrected,
                "corrections": corrections
            })
        
        return corrected
    
    def _is_dangerous(self, decision: Dict) -> bool:
        """Check if decision involves dangerous operations"""
        dangerous_patterns = [
            "rm -rf", "dd if=", "mkfs", "format",
            "> /dev/", "chmod 777", ":(){ :|:& };:"
        ]
        
        command = decision.get("command", "")
        if not command:  # Fix: Check if command is None or empty
            return False
        return any(pattern in command for pattern in dangerous_patterns)
    
    def _check_prerequisites(self, decision: Dict) -> List[str]:
        """Check for missing prerequisites"""
        prereqs = []
        
        # Check if tools are available
        required_tools = decision.get("required_tools", [])
        for tool in required_tools:
            if not decision.get("tools_available", {}).get(tool):
                prereqs.append(tool)
        
        return prereqs
    
    def _suggest_optimizations(self, decision: Dict) -> List[str]:
        """Suggest optimizations"""
        optimizations = []
        
        # Check if multiple steps can be combined
        steps = decision.get("steps", [])
        if len(steps) > 3:
            optimizations.append("Consider parallel execution")
        
        return optimizations
    
    def get_correction_stats(self) -> Dict:
        """Get statistics about corrections made"""
        return {
            "total_corrections": len(self.correction_history),
            "recent_corrections": self.correction_history[-5:]
        }


# MODULE 5: Decision Engine
class DecisionEngine:
    """
    Karar motoru - Hangi aksiyonun alınacağına karar verir
    """
    
    def __init__(self):
        self.decision_history = []
    
    def decide(self, analysis: Dict, context: ExecutionContext) -> Dict:
        """
        Make a decision based on analysis
        
        Returns:
            {
                "action": str,
                "command": str,
                "needs_approval": bool,
                "reasoning": str,
                "confidence": float
            }
        """
        intent = analysis.get("intent")
        steps = analysis.get("steps", [])
        risks = analysis.get("risks", [])
        
        # Determine if approval needed
        needs_approval = self._needs_approval(intent, risks, context)
        
        # Select best action
        action = self._select_action(steps, context)
        
        # Generate command if needed
        command = self._generate_command(action, context)
        
        decision = {
            "action": action,
            "command": command,
            "needs_approval": needs_approval,
            "reasoning": analysis.get("reasoning", ""),
            "confidence": analysis.get("confidence", 0.5),
            "has_risks": len(risks) > 0,
            "risks": risks,
            "steps": steps
        }
        
        self.decision_history.append(decision)
        return decision
    
    def _needs_approval(self, intent: str, risks: List[str], context: ExecutionContext) -> bool:
        """Determine if user approval is needed"""
        # Always ask on first run
        if not context.history:
            return True
        
        # Ask for risky operations
        if risks:
            return True
        
        # Ask for destructive intents
        if intent in ["exploit", "get_shell"]:
            return True
        
        return False
    
    def _select_action(self, steps: List[Dict], context: ExecutionContext) -> str:
        """Select the next action to take"""
        if not steps:
            return "respond"
        
        # Get first uncompleted step
        current_step = context.current_step
        if current_step < len(steps):
            return steps[current_step].get("action", "unknown")
        
        return "complete"
    
    def _generate_command(self, action: str, context: ExecutionContext) -> Optional[str]:
        """Generate shell command for action"""
        target = context.target
        
        if action == "port_scan" and target:
            return f"nmap -F {target}"
        elif action == "service_detection" and target:
            return f"nmap -sV {target}"
        elif action == "web_scan" and target:
            return f"nikto -h {target}"
        elif action == "vuln_scan" and target:
            return f"nmap --script vuln {target}"
        
        return None


# Brain Facade - Main interface
class DrakbenBrain:
    """
    Ana beyin interface - 5 modülü koordine eder
    Gerçek LLM entegrasyonu ile
    """
    
    def __init__(self, llm_client=None):
        # Auto-initialize LLM client if not provided
        if llm_client is None and LLM_AVAILABLE:
            try:
                llm_client = OpenRouterClient()
            except Exception:
                llm_client = None
        
        self.llm_client = llm_client
        
        # Initialize modules
        self.orchestrator = MasterOrchestrator()
        self.reasoning = ContinuousReasoning(llm_client)
        self.context_mgr = ContextManager()
        self.self_correction = SelfCorrection()
        self.decision_engine = DecisionEngine()
        
        # Connect modules
        self.orchestrator.initialize(
            self.reasoning,
            self.context_mgr,
            self.self_correction,
            self.decision_engine
        )
    
    def think(self, user_input: str, target: str = None) -> Dict:
        """
        AI-powered thinking - Ana giriş noktası
        
        Args:
            user_input: Kullanıcı komutu/sorusu
            target: Hedef IP/domain (opsiyonel)
        
        Returns:
            {
                "intent": str,
                "reply": str,
                "command": str (optional),
                "steps": list,
                "needs_approval": bool
            }
        """
        # Build context
        system_context = {
            "target": target,
            "llm_available": self.llm_client is not None
        }
        
        # Process through orchestrator
        result = self.process(user_input, system_context)
        
        # Format response
        return {
            "intent": result.get("action", "chat"),
            "reply": result.get("reasoning", ""),
            "command": result.get("command"),
            "steps": result.get("steps", []),
            "needs_approval": result.get("needs_approval", False),
            "confidence": result.get("confidence", 0.5),
            "risks": result.get("risks", []),
            "llm_response": result.get("llm_response")
        }
    
    def chat(self, message: str) -> str:
        """
        Direct chat with LLM
        
        Args:
            message: User message
            
        Returns:
            AI response string
        """
        if self.llm_client:
            return self.llm_client.query(message)
        else:
            return "[Offline Mode] LLM bağlantısı yok. config/api.env dosyasını kontrol edin."
    
    def process(self, user_input: str, system_context: Dict) -> Dict:
        """
        Main entry point - Process user request
        """
        return self.orchestrator.process_request(user_input, system_context)
    
    def get_context(self) -> Dict:
        """Get current context"""
        return self.context_mgr.get_full_context()
    
    def get_stats(self) -> Dict:
        """Get brain statistics"""
        return {
            "reasoning_history": len(self.reasoning.reasoning_history),
            "corrections_made": len(self.self_correction.correction_history),
            "decisions_made": len(self.decision_engine.decision_history),
            "llm_available": self.llm_client is not None
        }
    
    def test_llm(self) -> Dict:
        """Test LLM connection"""
        if not self.llm_client:
            return {"connected": False, "error": "No LLM client configured"}
        
        try:
            response = self.llm_client.query("Merhaba, çalışıyor musun?")
            is_error = response.startswith("[") and any(x in response for x in ["Error", "Offline", "Timeout"])
            return {
                "connected": not is_error,
                "provider": self.llm_client.get_provider_info(),
                "response": response[:200]
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}
