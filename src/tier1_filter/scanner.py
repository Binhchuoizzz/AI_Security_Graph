"""
DevSecOps SCA Scanner Utility

Module này thực hiện quét lỗ hổng tĩnh (Software Composition Analysis - SCA)
trên mã nguồn và các dependencies phụ thuộc của chính hệ thống (ví dụ: requirements.txt)
bằng công cụ Trivy. 

LƯU Ý: Đây KHÔNG PHẢI là module sinh log quét mạng giả lập hay tương tác
trực tiếp với runtime pipeline của SENTINEL. Mục đích của module này là:
  1. Quét lỗ hổng của chính hệ thống trước khi triển khai (Self-Securing).
  2. Xuất báo cáo dạng JSON lưu trữ tại data/trivy-results.json.
  3. Cung cấp tri thức bảo mật tĩnh để nạp vào Knowledge Graph (Neo4j).
"""

import subprocess
import json
import os
import logging

logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    """Wrapper for Trivy vulnerability scanner"""
    
    def __init__(self, target_dir="/app", output_file="data/trivy-results.json"):
        self.target_dir = target_dir
        self.output_file = output_file
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        
    def run_scan(self):
        """Runs Trivy scanner on the target directory"""
        logger.info(f"Running Trivy scan on {self.target_dir}...")
        
        try:
            # Check if trivy is installed
            subprocess.run(["trivy", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("Trivy is not installed or not in PATH. Skipping actual scan.")
            self._generate_mock_results()
            return self.output_file
            
        try:
            # Run the actual scan
            cmd = [
                "trivy", "fs", self.target_dir, 
                "--format", "json", 
                "--output", self.output_file,
                "--scanners", "vuln",
                "--skip-dirs", "data",
                "--skip-dirs", "knowledge_base"
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info(f"Trivy scan completed. Results saved to {self.output_file}")
            return self.output_file
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Trivy scan failed: {e.stderr.decode('utf-8')}")
            # Fallback to mock on error to keep pipeline flowing
            self._generate_mock_results()
            return self.output_file

    def _generate_mock_results(self):
        """Generates mock results if Trivy is not available"""
        mock_data = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-XXXX",
                            "PkgName": "mock-pkg",
                            "InstalledVersion": "1.0.0",
                            "Severity": "HIGH",
                            "Description": "Mock vulnerability for testing.",
                            "FixedVersion": "1.0.1"
                        }
                    ]
                }
            ]
        }
        with open(self.output_file, "w") as f:
            json.dump(mock_data, f, indent=2)
        logger.info(f"Generated mock Trivy results at {self.output_file}")
