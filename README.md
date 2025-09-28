# Projeto: Malware Simulado (Educação e Defesa)

> **Aviso de segurança:** este projeto tem fins exclusivamente educacionais. **Não** inclui código malicioso executável. Todos os exemplos práticos são **simulações seguras** ou pseudocódigo. Execute qualquer experimento apenas em máquinas virtuais isoladas (host-only), com snapshots e sem conexão à internet.

---

## Estrutura sugerida do repositório

```
/Projeto-Malware-Simulado
│
├─ README.md
├─ LICENSE
├─ /docs
│   ├─ lab-setup.md
│   ├─ defesa-e-deteccao.md
│   └─ relatorio_experimento.md
├─ /simulacoes
│   ├─ ransomware_concept.txt
│   └─ keylogger_concept.txt
├─ /scripts_defesa
│   ├─ integrity_monitor.py
│   └─ log_parser.py
├─ /images
└─ /references
    └─ artigos_links.md
```

---

## README.md (conteúdo principal)

### Título

**Malware Simulado — Projeto Educacional**

### Descrição

Este repositório reúne material para um projeto educacional sobre **comportamento e defesa contra malwares** (foco: ransomware e keylogger). O objetivo é **documentar** conceitos, mostrar pseudocódigo e exercícios defensivos seguros, e oferecer artefatos que podem ser usados para demonstrar técnicas de detecção e mitigação sem criar malware executável.

### Aviso de segurança

* **Não** execute qualquer código que você não entenda.
* Sempre utilize máquinas virtuais isoladas (host-only) e snapshots.
* Não publique binários maliciosos.

### Estrutura do repositório

(Ver seção "Estrutura sugerida do repositório".)

### Como reproduzir (modo seguro)

1. Crie duas VMs: *Atacante* (opcional) e *Alvo* (apenas para demonstração). Use VirtualBox ou VMware.
2. Configure rede **host-only** (sem NAT/bridge).
3. Faça snapshot das VMs antes de qualquer experimento.
4. Use apenas os scripts em `/scripts_defesa` e os arquivos em `/simulacoes` — estes são seguros e usados para demonstração.

### O que há neste projeto

* Documentação sobre setup de laboratório e medidas de defesa.
* Pseudocódigo explicativo para Ransomware e Keylogger (files em `/simulacoes`).
* Scripts **defensivos** (monitor de integridade e parser de logs) em `/scripts_defesa`.
* Relatório modelo para entrega do projeto.

### Referências

* MITRE ATT&CK
* OWASP
* Documentação do Sysmon
* Artigos acadêmicos e blogs de segurança (lista em `/references`)

---

## /docs/lab-setup.md (resumo)

### Requisitos

* Host com recursos para rodar 2 VMs (4GB+ RAM por VM recomendado)
* VirtualBox / VMware
* Snapshots habilitados

### Passos rápidos

1. Criar VM base (OS leve, ex: Ubuntu Server ou Windows 10 de teste).
2. Desativar adaptador de rede (ou usar Host-Only).
3. Tirar snapshot limpo.
4. Isolar pasta compartilhada entre host e VM para troca de artefatos **somente** se necessário.

### Boas práticas

* Trabalhe offline.
* Não usar contas pessoais.
* Documentar cada experimento e reverter ao snapshot após testar.

---

## /simulacoes/ransomware_concept.txt

**Ransomware — Conceito e simulação segura**

Objetivo: Demonstrar fluxo de um ransomware sem aplicar criptografia real que cause perda de dados.

Abordagem segura:

* Criar pasta `test_files/` com arquivos de exemplo.
* Em vez de cifrar, renomear arquivos adicionando sufixo `.locked_demo` e armazenar uma chave de demonstração em `recovery_key_demo.txt` local.
* Gerar um arquivo `README_RECOVERY_demo.txt` com mensagem de resgate (educacional)

Pseudocódigo explicativo (não executável):

```
para cada arquivo em test_files:
    se extensão do arquivo estiver na lista permitida:
        gerar demo_key (apenas para exibição)
        criar conteúdo_demo = pseudo_encrypt(file.content, demo_key)
        sobrescrever arquivo com conteúdo_demo
        renomear arquivo -> nome + ".locked_demo"
criar README_RECOVERY_demo.txt com instruções e demo_key
```

Observações:

* Documente como a cifra real funcionaria (chaves simétricas x assimétricas), vetores de persistência e exfiltração.
* Explique mitigação: backups offline, EDR, controle de privilégios e segmentação de rede.

---

## /simulacoes/keylogger_concept.txt

**Keylogger — Conceito e simulação segura**

Objetivo: Explicar captura de teclas e impactos sem executar captura global.

Abordagem segura:

* Criar um arquivo `simulated_input.txt` com linhas representando teclas digitadas.
* Implementar um programa que lê `simulated_input.txt` e grava `keylog_demo.txt` com timestamps.

Pseudocódigo:

```
abrir simulated_input.txt
para cada linha em simulated_input:
    timestamp = agora()
    append (timestamp + " " + linha) em keylog_demo.txt
```

Discussões extras:

* Técnicas reais: hooks em APIs, drivers de kernel, captura via JavaScript (web), etc.
* Mitigação: controles de endpoint, policies, EDR, atualizações, awareness de usuários.

---

## /scripts_defesa/integrity_monitor.py

**Descrição:** Script educativo que monitora alterações em uma pasta calculando checksums SHA256. Útil para detectar alterações inesperadas (por exemplo, cifragem de arquivos).

```python
#!/usr/bin/env python3
"""
integrity_monitor.py
Monitora uma pasta e grava um relatório de alterações comparando hashes SHA256.
Uso: python integrity_monitor.py /caminho/para/test_files
"""
import os
import sys
import hashlib
import json
from pathlib import Path

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def snapshot_folder(folder):
    folder = Path(folder)
    snapshot = {}
    for p in folder.rglob('*'):
        if p.is_file():
            try:
                snapshot[str(p)] = sha256_file(p)
            except Exception as e:
                snapshot[str(p)] = f"ERROR:{e}"
    return snapshot


def main():
    if len(sys.argv) != 2:
        print("Uso: python integrity_monitor.py /caminho/para/test_files")
        sys.exit(1)
    folder = sys.argv[1]
    snap_file = Path('snapshot.json')

    if not snap_file.exists():
        # primeira execução: cria snapshot inicial
        snap = snapshot_folder(folder)
        with open(snap_file, 'w') as f:
            json.dump(snap, f, indent=2)
        print('Snapshot inicial criado em snapshot.json')
        return

    # comparação
    with open(snap_file, 'r') as f:
        old_snap = json.load(f)

    new_snap = snapshot_folder(folder)

    added = [p for p in new_snap if p not in old_snap]
    removed = [p for p in old_snap if p not in new_snap]
    changed = [p for p in new_snap if p in old_snap and new_snap[p] != old_snap[p]]

    if not (added or removed or changed):
        print('Nenhuma alteração detectada')
    else:
        print('Alterações detectadas:')
        if added:
            print('\nArquivos adicionados:')
            for p in added:
                print(' +', p)
        if removed:
            print('\nArquivos removidos:')
            for p in removed:
                print(' -', p)
        if changed:
            print('\nArquivos modificados:')
            for p in changed:
                print(' *', p)

    # atualiza snapshot
    with open(snap_file, 'w') as f:
        json.dump(new_snap, f, indent=2)

if __name__ == '__main__':
    main()
```

---

## /scripts_defesa/log_parser.py

**Descrição:** Parser simples que varre uma pasta de logs e identifica artefatos com sufixos `*.locked_demo` (simulação de detecção de ransomware) e mensagens indicativas.

```python
#!/usr/bin/env python3
"""
log_parser.py
Procura por padrões simples em arquivos de log ou em diretórios de trabalho para sinalizar possíveis eventos suspeitos.
Uso: python log_parser.py /caminho/para/pasta_logs
"""
import sys
from pathlib import Path

PATTERNS = [".locked_demo", "README_RECOVERY_demo", "suspicious_upload"]


def scan_folder(folder):
    folder = Path(folder)
    results = []
    for p in folder.rglob('*'):
        try:
            if p.is_file():
                text = p.read_text(errors='ignore')
                for pat in PATTERNS:
                    if pat in text:
                        results.append((str(p), pat))
        except Exception:
            continue
    return results


def main():
    if len(sys.argv) != 2:
        print('Uso: python log_parser.py /caminho/para/pasta_logs')
        sys.exit(1)
    folder = sys.argv[1]
    hits = scan_folder(folder)
    if not hits:
        print('Nenhum artefato de demonstração encontrado')
    else:
        print('Artefatos detectados:')
        for f, pat in hits:
            print(f' - {f}  (padrão: {pat})')

if __name__ == '__main__':
    main()
```

---

## /docs/defesa-e-deteccao.md (resumo)

### Medidas preventivas

* Backups regulares e offline
* EDR com regras de detecção de comportamento
* Controle de privilégios (least privilege)
* Segmentar rede e limitar acesso a shares
* Hardening de endpoints e servidores

### Medidas reativas

* Isolamento do host afetado
* Recuperação via snapshot ou backups
* Análise forense (memdump, logs, timeline)
* Notificação e comunicação interna

### Ferramentas úteis

* Sysmon + ELK/Graylog
* YARA para regras de arquivo/processo
* Ferramentas de análise estática/dinâmica: Ghidra, strings, lsof, netstat

---

## /docs/relatorio_experimento.md (modelo de relatório)

1. **Introdução**: objetivos e escopo.
2. **Ambiente**: descrição das VMs, versões, rede isolada.
3. **Metodologia**: o que foi executado vs documentado.
4. **Resultados**: screenshots, saídas dos scripts defensivos, logs.
5. **Análise**: o que as simulações mostram sobre vetores de ataque.
6. **Mitigações**: recomendações práticas.
7. **Conclusão**: aprendizados e próximos passos.

---

## /references/artigos_links.md

* MITRE ATT&CK: [https://attack.mitre.org/](https://attack.mitre.org/)
* OWASP: [https://owasp.org/](https://owasp.org/)
* Sysmon (Microsoft Sysinternals)
* Artigos e whitepapers (incluir referências acadêmicas ou blogs confiáveis)

---


> Observação final: todos os scripts fornecidos em `/scripts_defesa` são **defensivos** e seguros para execução em ambiente de testes. As simulações em `/simulacoes` são pseudocódigo e arquivos explicativos — **não** realizam ações perigosas.
