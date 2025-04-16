	/**
 * Autor: Bruno Mendes dos Santos
 * Data de Criação: 2025-04-16
 * Descrição: Funções para Geração de regras CGNAT para Mirktoik e relatório de mapeamento
 *
 * Última Modificação por: Bruno Mendes dos Santos
 * e-mail:oryon.br@gmail.com
 * Data da Última Modificação: 2025-04-16
 */
        // Variáveis globais
        let mappingData = [];
        let publicNetworks = [];
        let perIPMappingData = [];
        
        // Função para abrir abas
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
        
        // Função para copiar para área de transferência
        function copyToClipboard(elementId) {
            var copyText = document.getElementById(elementId);
            copyText.select();
            copyText.setSelectionRange(0, 99999);
            document.execCommand("copy");
            alert("Conteúdo copiado para a área de transferência!");
        }
        
        // Função para download das regras
        function downloadRules() {
            const rules = document.getElementById("rulesOutput").value;
            const blob = new Blob([rules], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'regras-cgnat.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        
        // Função para download do mapeamento por IP
        function downloadPerIPMapping() {
            let content = "IP Privado,IP Público,Faixa de Portas\n";
            perIPMappingData.forEach(item => {
                content += `${item.privateIp},${item.publicIp},${item.portRange}\n`;
            });
            
            const blob = new Blob([content], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'mapeamento-ip-cgnat.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        
        // Função para calcular subredes para múltiplas redes
        function calculateSubnets(privateRanges, publicRanges, ratio) {
            try {
                // Validação básica dos inputs
                if (!privateRanges || !publicRanges || !ratio) {
                    throw new Error("Todos os campos são obrigatórios");
                }
                // Verifica se o ratio é válido
                const validRatios = [2, 4, 8, 16, 32, 64];
                if (!validRatios.includes(parseInt(ratio))) {
                    throw new Error("Por favor, selecione uma razão válida");
                }
                // Processa as redes privadas e públicas
                const privateNetworks = privateRanges.trim().split(/\s+/).map(range => ipNetwork(range));
                publicNetworks = publicRanges.trim().split(/\s+/).map(range => ipNetwork(range));
                // Verifica se temos redes públicas suficientes
                if (publicNetworks.length === 0 || privateNetworks.length !== publicNetworks.length) {
                    throw new Error("O número de redes privadas deve ser igual ao número de redes públicas");
                }
                // Calcula o prefixo para as sub-redes privadas
                const privateSubnetsByPublic = {};
                publicNetworks.forEach((publicNetwork, index) => {
                    const privateNetwork = privateNetworks[index];
                    const newPrefix = privateNetwork.prefixlen + Math.log2(ratio);
                    // Divide a rede privada em sub-redes
                    const subnets = privateNetwork.subnets(newPrefix);
                    // Verifica se temos sub-redes suficientes
                    if (subnets.length < ratio) {
                        throw new Error(`Rede privada ${privateNetwork.toString()} muito pequena para a razão especificada`);
                    }
                    privateSubnetsByPublic[publicNetwork.toString()] = subnets.slice(0, ratio);
                });
                return {
                    privateSubnetsByPublic: privateSubnetsByPublic,
                    ratio: ratio
                };
            } catch (error) {
                throw error;
            }
        }
        
        // Função principal para gerar regras no novo formato com mapeamento direto privado-público
        function generateRules() {
            const privateRanges = document.getElementById("privateRange").value.trim();
            const publicRanges = document.getElementById("publicRange").value.trim();
            const ratio = parseInt(document.getElementById("ratio").value);
            
            try {
                const {privateSubnetsByPublic, ratio: ratioValue} = calculateSubnets(privateRanges, publicRanges, ratio);
                // Gerar regras no formato solicitado
                let rules = [];
                mappingData = []; // Resetar dados de mapeamento
                perIPMappingData = []; // Resetar dados de mapeamento por IP
                
                // Adiciona as regras de blackhole para cada rede pública
                for (const publicNetwork of publicNetworks) {
                    rules.push(`/ip route add comment=BLACKHOLE-CGNAT distance=1 dst-address=${publicNetwork.toString()} type=blackhole`);
                }
                rules.push("");
                
                // Para cada par de redes privadas e públicas, adiciona as regras específicas
                Object.entries(privateSubnetsByPublic).forEach(([publicNetworkStr, privateSubnets]) => {
                    const publicNetwork = ipNetwork(publicNetworkStr);
                    // Adiciona address-list para esta rede pública específica
                    privateSubnets.forEach(subnet => {
                        rules.push(`/ip firewall address-list add address=${subnet.toString()} list=CGNAT-${publicNetwork.toString()}`);
                    });
                    
                });
                rules.push("");
                
                // Adiciona address-list para no-wfp-cgnat
                rules.push(`/ip firewall address-list remove [find list=no-wfp-cgnat]`);
                rules.push(`/ip firewall address-list add address=10.0.0.0/8 list=no-wfp-cgnat`);
                rules.push(`/ip firewall address-list add address=172.16.0.0/12 list=no-wfp-cgnat`);
                rules.push(`/ip firewall address-list add address=192.168.0.0/16 list=no-wfp-cgnat`);
                rules.push(`/ip firewall address-list add address=100.64.0.0/10 list=no-wfp-cgnat`);
                rules.push("");
                
                // Adiciona regras de firewall e configurações de sistema
                rules.push(`/ip firewall filter add action=fasttrack-connection chain=forward`);
                rules.push(`/ip firewall filter add action=accept chain=forward`);
                rules.push(`/system resource irq rps en [f]`);
                rules.push("");
                
                // Adiciona o jump principal para CGNAT
                rules.push(`/ip firewall nat add action=jump chain=srcnat comment=JUMP-CGNAT jump-target=CGNAT src-address=100.64.0.0/10`);
                
                // Para cada rede pública, adiciona os jumps específicos
                Object.entries(privateSubnetsByPublic).forEach(([publicNetworkStr, privateSubnets]) => {
                    const publicNetwork = ipNetwork(publicNetworkStr);
                    rules.push(`/ip firewall nat add action=jump chain=CGNAT comment="wfp-cgnat-${publicNetwork.toString()} (jump --> tcp)" dst-address-list=!no-wfp-cgnat jump-target="wfp-cgnat-${publicNetwork.toString()} (jump --> tcp)" protocol=tcp src-address-list=CGNAT-${publicNetwork.toString()}`);
                    rules.push(`/ip firewall nat add action=jump chain=CGNAT comment="wfp-cgnat-${publicNetwork.toString()} (jump --> udp)" dst-address-list=!no-wfp-cgnat jump-target="wfp-cgnat-${publicNetwork.toString()} (jump --> udp)" protocol=udp src-address-list=CGNAT-${publicNetwork.toString()}`);
                    rules.push(`/ip firewall nat add action=jump chain=CGNAT comment="wfp-cgnat-${publicNetwork.toString()} (jump --> all)" dst-address-list=!no-wfp-cgnat jump-target="wfp-cgnat-${publicNetwork.toString()} (jump --> all)" src-address-list=CGNAT-${publicNetwork.toString()}`);
                });
                
                // Calcula a divisão de portas
                const totalPorts = 65535 - 1024 + 1;  // 64.512 portas no total
                const portsPerSubnet = Math.floor(totalPorts / ratio);
                
                // Para cada par de redes privadas e públicas, adiciona as regras netmap para TCP, UDP e ALL
                Object.entries(privateSubnetsByPublic).forEach(([publicNetworkStr, privateSubnets], networkIndex) => {
                    const publicNetwork = ipNetwork(publicNetworkStr);
                    let initialPort = 1024;
                    privateSubnets.forEach((subnet, subnetIndex) => {
                        let finalPort = initialPort + portsPerSubnet - 1;
                        if (subnetIndex === privateSubnets.length - 1) {
                            finalPort = 65535;
                        }
                        // Regras TCP
                        rules.push(`/ip firewall nat add action=netmap chain="wfp-cgnat-${publicNetwork.toString()} (jump --> tcp)" comment="wfp-cgnat-${publicNetwork.toString()} [${initialPort}-${finalPort}]" protocol=tcp src-address=${subnet.toString()} to-addresses=${publicNetwork.toString()} to-ports=${initialPort}-${finalPort}`);
                        
                        // Gerar mapeamento IP a IP
                        generateIpMapping(subnet, publicNetwork.toString(), initialPort, finalPort);
                        initialPort = finalPort + 1;
                    });
                    
                    // Resetar porta inicial para regras UDP
                    initialPort = 1024;
                    privateSubnets.forEach((subnet, subnetIndex) => {
                        let finalPort = initialPort + portsPerSubnet - 1;
                        if (subnetIndex === privateSubnets.length - 1) {
                            finalPort = 65535;
                        }
                        // Regras UDP
                        rules.push(`/ip firewall nat add action=netmap chain="wfp-cgnat-${publicNetwork.toString()} (jump --> udp)" comment="wfp-cgnat-${publicNetwork.toString()} [${initialPort}-${finalPort}]" protocol=udp src-address=${subnet.toString()} to-addresses=${publicNetwork.toString()} to-ports=${initialPort}-${finalPort}`);
                        initialPort = finalPort + 1;
                    });
                    
                    // Para cada sub-rede privada, adiciona as regras ALL (sem portas)
                    privateSubnets.forEach((subnet, subnetIndex) => {
                        const initialPort = 1024 + subnetIndex * portsPerSubnet;
                        let finalPort = 1024 + (subnetIndex + 1) * portsPerSubnet - 1;
                        if (subnetIndex === privateSubnets.length - 1) {
                            finalPort = 65535;
                        }
                        // Portas apenas para comentário, não usadas na regra ALL
                        rules.push(`/ip firewall nat add action=netmap chain="wfp-cgnat-${publicNetwork.toString()} (jump --> all)" comment="wfp-cgnat-${publicNetwork.toString()} [${initialPort}-${finalPort}]" src-address=${subnet.toString()} to-addresses=${publicNetwork.toString()}`);
                    });
                });
                
                // Exibe as regras
                document.getElementById("rulesOutput").value = rules.join("\n");
                
                // Gera a visualização SVG de subredes
                generateSvgVisualization(privateRanges, publicRanges, ratio, privateSubnetsByPublic);
                
                // Gera a visualização SVG de mapeamento por IP
                generatePerIPSvgVisualization();
                
                // Mostra a seção de output
                document.getElementById("outputSection").style.display = "block";
            } catch (error) {
                alert(`Erro: ${error.message}`);
            }
        }

        function generateIpMapping(privateSubnet, publicNetworkStr, initialPort, finalPort) {
            const publicNetwork = ipNetwork(publicNetworkStr);
            const publicIps = Array.from(publicNetwork.hosts());
            let publicIpIndex = 0;
            
            // Listar todos os IPs da sub-rede privada
            const privateIps = Array.from(ipNetwork(privateSubnet.toString()).hosts());
            
            privateIps.forEach(privateIp => {
                if (publicIpIndex >= publicIps.length) {
                    publicIpIndex = 0; // Volta ao primeiro IP público se acabarem
                }
                
                perIPMappingData.push({
                    privateIp: privateIp,
                    publicIp: publicIps[publicIpIndex],
                    portRange: `${initialPort}-${finalPort}`
                });
                
                publicIpIndex++;
            });
        }
        
        function generatePerIPSvgVisualization() {
            const svgWidth = 1000;
            const rowHeight = 30;
            const headerHeight = 40;
            const titleHeight = 120;
            const maxRows = 10000;  // Limitar o número de linhas para evitar SVGs enormes
            
            // Limitar o número de entradas para a exibição
            const displayData = perIPMappingData.slice(0, maxRows);
            const svgHeight = titleHeight + headerHeight + (displayData.length * rowHeight);
            
            let svgContent = `
                <svg width="${svgWidth}" height="${svgHeight}" viewBox="0 0 ${svgWidth} ${svgHeight}" xmlns="http://www.w3.org/2000/svg">
                    <rect width="100%" height="100%" fill="#f0f0f0"/>
                    <text x="${svgWidth/2}" y="30" font-family="Arial" font-size="20" text-anchor="middle" fill="black">Mapeamento por IP</text>
                    <text x="50" y="70" font-family="Arial" font-size="14" fill="black">Total de IPs mapeados: ${perIPMappingData.length}</text>
                    ${perIPMappingData.length > maxRows ? 
                        `<text x="50" y="90" font-family="Arial" font-size="14" fill="#e74c3c">Exibindo apenas ${maxRows} IPs. Baixe o arquivo completo para visualizar todos.</text>` : ''}
                    
                    <!-- Cabeçalho da tabela -->
                    <rect x="50" y="${titleHeight}" width="900" height="${headerHeight}" fill="#4CAF50" rx="5"/>
                    <text x="200" y="${titleHeight + 25}" font-family="Arial" font-size="14" text-anchor="middle" fill="white">IP Privado</text>
                    <text x="500" y="${titleHeight + 25}" font-family="Arial" font-size="14" text-anchor="middle" fill="white">IP Público</text>
                    <text x="800" y="${titleHeight + 25}" font-family="Arial" font-size="14" text-anchor="middle" fill="white">Faixa de Portas</text>
            `;
            
            let currentY = titleHeight + headerHeight;
            let rowColor = true;
            
            displayData.forEach((mapping, index) => {
                const fillColor = rowColor ? "#ffffff" : "#f9f9f9";
                rowColor = !rowColor;
                
                svgContent += `
                    <rect x="50" y="${currentY}" width="900" height="${rowHeight}" fill="${fillColor}" stroke="#ddd" stroke-width="1"/>
                    <text x="200" y="${currentY + 20}" font-family="Arial" font-size="12" text-anchor="middle" fill="black">${mapping.privateIp}</text>
                    <text x="500" y="${currentY + 20}" font-family="Arial" font-size="12" text-anchor="middle" fill="black">${mapping.publicIp}</text>
                    <text x="800" y="${currentY + 20}" font-family="Arial" font-size="12" text-anchor="middle" fill="black">${mapping.portRange}</text>
                `;
                
                currentY += rowHeight;
            });
            
            svgContent += `</svg>`;
            document.getElementById("perIPSvgContainer").innerHTML = svgContent;
        }
        
        function generateSvgVisualization(privateRanges, publicRanges, ratio, privateSubnetsByPublic) {
            const svgWidth = 1000;
            const totalPrivateSubnets = Object.values(privateSubnetsByPublic).reduce((acc, val) => acc + val.length, 0);
            const svgHeight = 400 + (totalPrivateSubnets * 30);
            const container = document.getElementById("svgContainer");
            
            const totalPorts = 65535 - 1024 + 1;
            const portsPerSubnet = Math.floor(totalPorts / ratio);
            
            let svgContent = `
                <svg width="${svgWidth}" height="${svgHeight}" viewBox="0 0 ${svgWidth} ${svgHeight}" xmlns="http://www.w3.org/2000/svg">
                    <rect width="100%" height="100%" fill="#f0f0f0"/>
                    <text x="${svgWidth/2}" y="30" font-family="Arial" font-size="20" text-anchor="middle" fill="black">Mapeamento por Sub-Rede</text>
                    <text x="50" y="70" font-family="Arial" font-size="16" fill="black">Rede(s) Privada(s): ${privateRanges}</text>
                    <text x="50" y="90" font-family="Arial" font-size="16" fill="black">Rede(s) Pública(s): ${publicRanges}</text>
                    <text x="50" y="110" font-family="Arial" font-size="16" fill="black">Razão: 1:${ratio} (1 público para ${ratio} privados)</text>
                    
                    <!-- Cabeçalho da tabela com nova ordem de colunas -->
                    <rect x="50" y="160" width="900" height="40" fill="#4CAF50" rx="5"/>
                    <text x="200" y="185" font-family="Arial" font-size="14" text-anchor="middle" fill="white">Rede Pública</text>
                    <text x="450" y="185" font-family="Arial" font-size="14" text-anchor="middle" fill="white">Faixa de Portas</text>
                    <text x="700" y="185" font-family="Arial" font-size="14" text-anchor="middle" fill="white">Rede Privada</text>
            `;
            
            let currentY = 210;
            let rowColor = true;
            
            Object.entries(privateSubnetsByPublic).forEach(([publicNetworkStr, privateSubnets]) => {
                const publicNetwork = ipNetwork(publicNetworkStr);
                let initialPort = 1024;
                
                privateSubnets.forEach((subnet, index) => {
                    let finalPort = initialPort + portsPerSubnet - 1;
                    if (index === privateSubnets.length - 1) {
                        finalPort = 65535;
                    }
                    
                    const fillColor = rowColor ? "#ffffff" : "#f9f9f9";
                    rowColor = !rowColor;
                    
                    svgContent += `
                        <rect x="50" y="${currentY}" width="900" height="30" fill="${fillColor}" stroke="#ddd" stroke-width="1"/>
                        
                        <!-- Coluna Rede Pública (agora primeira coluna) -->
                        <text x="200" y="${currentY + 20}" font-family="Arial" font-size="12" text-anchor="middle" fill="black">${publicNetworkStr}</text>
                        
                        <!-- Coluna Faixa de Portas -->
                        <text x="450" y="${currentY + 20}" font-family="Arial" font-size="12" text-anchor="middle" fill="black">${initialPort}-${finalPort}</text>
                        
                        <!-- Coluna Rede Privada (agora última coluna) -->
                        <text x="700" y="${currentY + 20}" font-family="Arial" font-size="12" text-anchor="middle" fill="black">${subnet}</text>
                    `;
                    
                    currentY += 30;
                    initialPort = finalPort + 1;
                });
            });
            
            svgContent += `</svg>`;
            container.innerHTML = svgContent;
        }
        
        // Funções auxiliares para manipulação de redes IP
        function ipNetwork(cidr) {
            const [ip, prefix] = cidr.split('/');
            const ipParts = ip.split('.').map(Number);
            const prefixLen = parseInt(prefix);
            if (isNaN(prefixLen) || prefixLen < 0 || prefixLen > 32) {
                throw new Error("Máscara de rede inválida");
            }
            
            // Calcula o endereço de rede em formato longo
            const ipLong = ipToLong(ip);
            const networkMask = (-1 << (32 - prefixLen)) >>> 0;
            const networkLong = ipLong & networkMask;
            const broadcastLong = networkLong | (~networkMask >>> 0);
            
            return {
                network: ip,
                prefixlen: prefixLen,
                toString: function() { return `${this.network}/${this.prefixlen}`; },
                hosts: function*() {
                    for (let current = networkLong + 1; current < broadcastLong; current++) {
                        yield longToIp(current);
                    }
                },
                subnets: function(newPrefix) {
                    const subnets = [];
                    const subnetCount = Math.pow(2, newPrefix - this.prefixlen);
                    const increment = Math.pow(2, 32 - newPrefix);
                    for (let i = 0; i < subnetCount; i++) {
                        const newIp = longToIp(networkLong + i * increment);
                        subnets.push(ipNetwork(`${newIp}/${newPrefix}`));
                    }
                    return subnets;
                }
            };
        }
        
        function ipToLong(ip) {
            const octets = ip.split('.').map(Number);
            if (octets.length !== 4 || octets.some(isNaN)) {
                throw new Error("Endereço IP inválido");
            }
            return (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
        }
        
        function longToIp(long) {
            return [
                (long >>> 24) & 0xff,
                (long >>> 16) & 0xff,
                (long >>> 8) & 0xff,
                long & 0xff
            ].join('.');
        }
        
        // Atualizar informações da razão quando selecionada
        document.getElementById("ratio").addEventListener('change', function() {
            const ratio = parseInt(this.value);
            const portsPerPrivateIp = Math.floor((65535 - 1024) / ratio);
            document.getElementById("ratioInfo").textContent = `Cada IP privado terá aproximadamente ${portsPerPrivateIp.toLocaleString()} portas disponíveis`;
        });

