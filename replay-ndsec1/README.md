# Arquivos do replay do dataset NDSec-1

## Dataset NDSec-1
https://www2.hs-fulda.de/NDSec/NDSec-1/  
https://www2.hs-fulda.de/NDSec/NDSec-1/Files/  

Grupo do dataset utilizado na replicação : *Botnet*

## Tráfego SYN-Flood
 - *botnet_SYN-FLOOD.pcap* : Tráfego SYN-Flood original;
 - *botnet_SYN-FLOOD_syn.pcap* : Apenas os pacotes SYN;
 - *botnet_SYN-FLOOD_syn_mac-ip-mod_fix-chksum.pcap* : Pacotes SYN com endereços MAC e IP alterados, e checksums recalculados.
 
## Tráfego Normal
 - *botnet_NORMAL.pcap* : Tráfego Normal original;
 - *botnet_NORMAL_mac-ip-httphost-mod_fix-chksum.pcap* : Tráfego Normal com endereços MAC, IP, HTTP Host alterados, e checksums recalculados;
 - *botnet_NORMAL_mac-ip-httphost-mod_fix-chksum_requests_0.gor* : Requisições HTTP extraídas do PCAP anterior com a ferramenta GoReplay para replicação.

## Tráfego Replicado
 - *botnet_NORMAL_replay_goreplay.pcap* : Tráfego Normal replicado com a ferramenta GoReplay;
 - *botnet_SYN-FLOOD_replay_moongen.pcap* : Tráfego SYN-Flood replicado com a ferramenta GopherCap;
 - *botnet_SYN-FLOOD_replay_moongen.pcap* : Tráfego SYN-Flood replicado com a ferramenta MoonGen;
 - *botnet_SYN-FLOOD_replay_tcpreplay.pcap* : Tráfego SYN-Flood replicado com a ferramenta Tcpreplay.

## Códigos Python
 - *agent-gnocchi-offline.py* : Script para coletar as métricas de nuvem no banco de dados Gnocchi;
 - *botnet_extract_normal_syn-flood.py* : Script para extrair os tráfegos Normal/Syn-Flood do dataset NDSec-1 e gerar os arquivos PCAP para replicação;
 - *edit_http_request_pcap.py* : Script para editar os campos *Host* e *Referer* do cabeçalho HTTP;
 - *edit_mac_ip_pcap.py* : Script para alterar os endereços IP e MAC dos pacotes;
 - *edit_packet_timestamp.py* : Script para editar a precisão (casas decimais) do timestamp para extrair os pacotes corretamente;
 
Para corrigir os checksums IP/TCP dos pacotes foi utilizada a ferramenta `tcprewrite`.
```
$ tcprewrite -C -i <INFILE.pcap> -o <OUTFILE.pcap>
```

## Dataset de Telemetria Gerado
Para compor o dataset foram considerados os dados coletados a partir da replicação dos traces com as ferramentas GoReplay e Tcpreplay.

- *telemetry_dataset_replay.csv* : Dataset de telemetria;
- *telemetry_normal_goreplay.csv* : Telemetria do tráfego Normal replicado com a ferramenta GoReplay;
- *telemetry_syn-flood_gophercap.csv* : Telemetria do tráfego SYN-Flood replicado com a ferramenta GopherCap.
- *telemetry_syn-flood_moongen.csv* : Telemetria do tráfego SYN-Flood replicado com a ferramenta Moongen.
- *telemetry_syn-flood_tcpreplay.csv*: Telemetria do tráfego SYN-Flood replicado com a ferramenta Tcpreplay.
