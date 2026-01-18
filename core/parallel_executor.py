#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# core/parallel_executor.py
# DRAKBEN Parallel Execution Engine - Threading Support

import threading
import queue
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Callable, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ParallelExecutor:
    """
    Multi-threaded command execution for DRAKBEN
    Solves: Single-threaded bottleneck
    """
    
    def __init__(self, max_workers: int = 4):
        """Initialize parallel executor with thread pool"""
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.results = {}
        self.lock = threading.Lock()
        
    def execute_command(self, command: str, timeout: int = 300) -> Dict[str, Any]:
        """Execute single command with timeout"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "status": "success",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "command": command
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "error": f"Command timed out after {timeout}s",
                "command": command
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "command": command
            }
    
    def execute_parallel_commands(self, commands: List[str], 
                                 max_workers: int = None) -> List[Dict]:
        """
        Execute multiple commands in parallel
        
        Usage:
            results = executor.execute_parallel_commands([
                "nmap -sS 192.168.1.0/24",
                "nmap -sU 192.168.1.0/24",
                "nmap -sV 192.168.1.0/24"
            ], max_workers=3)
        """
        if max_workers:
            self.max_workers = max_workers
        
        futures = {}
        results = []
        
        logger.info(f"Starting parallel execution of {len(commands)} commands with {self.max_workers} workers")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for i, cmd in enumerate(commands):
                future = executor.submit(self.execute_command, cmd)
                futures[future] = i
            
            # Collect results as they complete
            for future in as_completed(futures):
                result = future.result()
                idx = futures[future]
                result["index"] = idx
                results.append(result)
                logger.info(f"[{idx+1}/{len(commands)}] Completed: {result['command'][:50]}...")
        
        # Sort by original index
        results.sort(key=lambda x: x["index"])
        return results
    
    def execute_chain_parallel(self, chain: List[Dict], 
                              workers_per_stage: int = 2) -> Dict:
        """
        Execute chain stages in parallel where possible
        
        Chain format:
        [
            {"stage": 1, "commands": ["cmd1", "cmd2"]},
            {"stage": 2, "commands": ["cmd3"]}
        ]
        """
        output = {"stages": []}
        
        for stage in chain:
            stage_num = stage.get("stage", 1)
            commands = stage.get("commands", [])
            
            logger.info(f"Processing stage {stage_num} with {len(commands)} commands")
            
            # Execute all commands in stage in parallel
            stage_results = self.execute_parallel_commands(
                commands, 
                max_workers=workers_per_stage
            )
            
            output["stages"].append({
                "stage": stage_num,
                "command_count": len(commands),
                "results": stage_results,
                "status": "completed"
            })
        
        return output
    
    def execute_with_callback(self, commands: List[str], 
                            callback: Callable[[Dict], None]) -> None:
        """Execute commands with callback for real-time processing"""
        def worker(cmd, index):
            result = self.execute_command(cmd)
            result["index"] = index
            callback(result)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                executor.submit(worker, cmd, i) 
                for i, cmd in enumerate(commands)
            ]
            for future in as_completed(futures):
                future.result()
    
    def shutdown(self):
        """Gracefully shutdown executor"""
        self.executor.shutdown(wait=True)
        logger.info("ParallelExecutor shutdown complete")


class BatchExecutor:
    """Batch execution with progress tracking"""
    
    def __init__(self, batch_size: int = 10):
        self.batch_size = batch_size
        self.executor = ParallelExecutor(max_workers=4)
    
    def execute_targets_batch(self, targets: List[str], 
                             command_template: str) -> Dict:
        """
        Execute command against multiple targets in batches
        
        Usage:
            results = batch_executor.execute_targets_batch(
                ["192.168.1.1", "192.168.1.2", ...],
                "nmap -sS {target}"
            )
        """
        total = len(targets)
        batches = [
            targets[i:i + self.batch_size] 
            for i in range(0, total, self.batch_size)
        ]
        
        all_results = []
        
        for batch_num, batch in enumerate(batches):
            logger.info(f"Processing batch {batch_num + 1}/{len(batches)}")
            
            commands = [
                command_template.format(target=t) 
                for t in batch
            ]
            
            batch_results = self.executor.execute_parallel_commands(commands)
            all_results.extend(batch_results)
        
        return {
            "total_targets": total,
            "batch_size": self.batch_size,
            "batches": len(batches),
            "results": all_results
        }


# Example Usage
if __name__ == "__main__":
    # Test parallel execution
    executor = ParallelExecutor(max_workers=4)
    
    commands = [
        "echo 'Test 1' && sleep 1",
        "echo 'Test 2' && sleep 2",
        "echo 'Test 3' && sleep 1",
    ]
    
    results = executor.execute_parallel_commands(commands)
    
    for result in results:
        print(f"Command: {result['command']}")
        print(f"Status: {result['status']}")
        print(f"Output: {result.get('stdout', result.get('error'))}\n")
    
    executor.shutdown()
