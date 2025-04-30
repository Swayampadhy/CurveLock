# CurveLock
A mordern ransomware designed from scratch to infect faster and encrypt target contents using Elliptical Curve Cryptography (ECC) algorithm. For implementation details, visit -> https://swayampadhy.gitbook.io/root/projects/curvelock

## Disclaimer 
This project is a demonstration and should not be used maliciously. Developing or deploying ransomware without explicit permission is illegal and unethical. The author is not responsible for any misuse of this code.

## Features Of CurveLock - 
1. Utilizes Api Hammering to obfuscate call stack of the ransomware to evade detection from sandbox environments
2. Creates a random compile time IAT seed to evade static detection
3. Unhooks NTDll by creating a suspended process, copying the clean Ntdll from it and replacing out NTDll in the `.text` section
4. Extracts process token and checks it's elevation and integrity and determines it it is being run as Admin or not.
5. If not being run as admin, it exploits CVE-2024-6769 to create a new process with high integrity token. Cve Link -> https://github.com/fortra/CVE-2024-6769/tree/main
6. Exploits DcSync using the DCSyncer tool (https://github.com/notsoshant/DCSyncer) to extract username and NTLM hash combinations from the domain controller and parses it.
7. Performs self deletion to avoid manual analysis after execution.
8. Embeds the Ransomware Payload into a `.PNG` file's IDAT sections and encrypts each section with it's own RC4 key.
9. Payload is extracted from the `.PNG` file at runtime and executed.
10. Also provides the decryptor for the encrypted files.

## Steps To Run

1. Build The Solution
2. Host all the required exploits and the files given in "Attacker Server Files" in a web server. Also edit the hardcoded IP addresses in CurveLock project.
3. Execute the CurveLock binary in the target machine.

## Results
#### CurveLock

1. Execution In Unprivileged Context and Privilege Escalation

<img width="980" alt="Execution_unprivileged_context_and_exploit_initial_stage" src="https://github.com/user-attachments/assets/6f545409-d172-4c07-8c6e-b12fb15b0b5e" />

<img width="947" alt="Exploit_stage_two" src="https://github.com/user-attachments/assets/26b6435f-fcf4-480b-ad5a-0df05307b0eb" />

2. Credential Dumping Using DCSyncer

<img width="960" alt="Credential_Dumping_Using_DCSync" src="https://github.com/user-attachments/assets/c28c05c3-0b1e-4baf-aea7-c8748f505de4" />

3. Decryptor Download Success/Failure

<img width="487" alt="Decryptor_successful_download" src="https://github.com/user-attachments/assets/b7717426-f727-4b6c-83b4-36c558dd0351" />

<img width="324" alt="Decryptor_download_failed" src="https://github.com/user-attachments/assets/af646474-d6e4-4ffd-beb2-9d848c84c360" />

4. Attacker Server Output

<img width="793" alt="files_being_downloaded_from_attacker_server" src="https://github.com/user-attachments/assets/ddf34bcc-e55c-422a-bee1-ac123f34ac15" />

#### CurveLock Payload

1. Before Execution Of Payload

<img width="806" alt="Before_Execution_Of_Payload" src="https://github.com/user-attachments/assets/ad191e3b-00fd-4d27-ac8a-8ab0e13d78de" />

2. After Execution Of Payload

<img width="1179" alt="After_execution_Of_Payload" src="https://github.com/user-attachments/assets/0bf814a5-9a88-440d-8848-47e9cd755864" />

3. Payload dealing with BlackListed extensions

<img width="1045" alt="payload_blacklisted_extension" src="https://github.com/user-attachments/assets/7b6d1271-f3b8-4c7c-a2bd-e53ceebe6849" />

4. Decryptor Output

<img width="855" alt="Decryptor_Output" src="https://github.com/user-attachments/assets/cf5bf938-e09f-4173-bf79-696600db6c1b" />

## Credits
I thank @Maldev-Academy for providing me with knowledge to build this malware. I would also like to thank @notsoshant and @fortra for DcSyncer and CVE-2024-6769 POC respectively.


