# Arquivos do replay do dataset NDSec-1

## Dataset NDSec-1
https://www2.hs-fulda.de/NDSec/NDSec-1/  
https://www2.hs-fulda.de/NDSec/NDSec-1/Files/  

Grupo do dataset utilizado na replicação : *Botnet*

## Tráfego SYN-Flood
 - *botnet_SYN-FLOOD.pcap* : Tráfego SYN-Flood original;
 - *botnet_SYN-FLOOD_mac-ip_mod.pcap* : Tráfego SYN-Flood com MAC e IP alterados.
 
## Tráfego Normal
 - *botnet_NORMAL.pcap* : Tráfego Normal original;
 - *botnet_NORMAL_mac-ip_mod.pcap* : Tráfego Normal com MAC e IP alterados;
 - *botnet_NORMAL_mac-ip_mod_httphost_mod.pcap* : Tráfego Normal com MAC, IP e HTTP host/referer alterados.

## Tráfego Replicado
 - *botnet_NORMAL_replay.pcap* : Tráfego Normal replicado com o script desenvolvido;
 - *botnet_SYN-FLOOD_replay_moongen.pcap* : Tráfego SYN-Flood replicado com a ferramenta MoonGen;
 - *botnet_SYN-FLOOD_replay_tcpreplay.pcap* : Tráfego SYN-Flood replicado com a ferramenta Tcpreplay.

## Códigos Python
 - *agent-gnocchi-offline.py* : Script para coletar as métricas no Gnocchi;
 - *botnet_extract_normal_syn-flood.py* : Script para extrair os tráfegos Normal/Syn-Flood do dataset NDSec-1 e gerar os arquivos PCAP para replicação;
 - *edit_http_request_pcap.py* : Script para editar os campus *Host* e *Referer* do cabeçalho HTTP;
 - *edit_packet_timestamp.py* : Script para editar a precisão (casas decimais) do timestamp para extrair os pacotes corretamente;
 - *replay_normal.py* : Script para replicar o tráfego normal utilizando Python Requests.

## Dataset de Telemetria Gerado
 - *telemetry_dataset_normal.csv* : Dataset de telemetria do tráfego Normal;
 - *telemetry_dataset_syn-flood.csv* : Dataset de telemetria do tráfego SYN-Flood.
