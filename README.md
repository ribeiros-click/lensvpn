# LensVPN

Cliente OpenVPN para macOS escrito do zero, sem depender do OpenVPN instalado.

- **`ovpnc.py`**: o motor do protocolo OpenVPN, só com a biblioteca padrão do Python e a CommonCrypto do macOS.
- **`OVPNBar/`**: app de barra de menus em SwiftUI, com várias conexões simultâneas.

## Download

Baixe o `.dmg` em [Releases](../../releases) ou nos artefatos do workflow **build**, e arraste o OVPNBar para Aplicativos.

O app não é assinado com Developer ID. Na primeira abertura, clique com o botão direito e escolha **Abrir**, ou rode:

```bash
xattr -dr com.apple.quarantine /Applications/OVPNBar.app
```

## App (OVPNBar)

- Ícone na barra de menus com o estado das conexões e a contagem de conexões ativas.
- Várias conexões simultâneas, cada uma com seu próprio processo e sua interface `utun`.
- Importa um ou vários `.ovpn`. Certificados e chaves em arquivos separados são embutidos no perfil. Também abre `.ovpn` pelo "Abrir com" do Finder.
- Exporta um perfil ou todos de uma vez para uma pasta.
- Senhas no Keychain, log por conexão, domínios DNS internos, opção de abrir com o sistema.

### Motor privilegiado

Criar interfaces `utun` e mexer em rotas exige root. Na primeira conexão o app pede a senha de administrador uma única vez para:

1. copiar o `ovpnc.py` para `/usr/local/libexec/ovpnbar/`, com dono `root` e sem permissão de escrita para o usuário;
2. criar `/etc/sudoers.d/ovpnbar`, que permite ao usuário atual rodar **apenas** esse motor via `sudo` sem senha.

Para desfazer, use **Configurações → Remover motor de VPN…**.

## Motor (`ovpnc.py`)

O que está implementado:

- tls-auth
- camada de confiabilidade do canal de controle
- TLS via `ssl.MemoryBIO`, com `verify-x509-name` e `remote-cert-tls`
- key-method 2 e `auth-user-pass`
- PUSH_REPLY com NCP e peer-id
- canal de dados AES-GCM (P_DATA_V1/V2) e AES-CBC+HMAC
- utun, rotas, redirect-gateway e DNS por domínio
- ping/ping-restart, renegociação, explicit-exit-notify e reconexão

Uso pela linha de comando:

```bash
python3 ovpnc.py perfil.ovpn --test        # testa servidor + certificado (sem root)
sudo python3 ovpnc.py perfil.ovpn          # conecta
sudo python3 ovpnc.py perfil.ovpn -v --dns-domain empresa.local
```

Limitações:

- só UDP;
- sem compressão (só o enquadramento de pacote não comprimido);
- sem CHACHA20 e sem `tls-crypt`;
- DNS só por domínio, sem trocar o resolvedor principal.

## Build

São necessárias as ferramentas do Xcode.

```bash
OVPNBar/build.sh             # gera OVPNBar/build/OVPNBar.app (universal)
OVPNBar/build.sh --dmg       # gera também o .dmg
OVPNBar/build.sh --install   # copia para /Applications
python3 -I tests/test_engine.py
```

Um push de tag `v*` gera o DMG no CI e o anexa ao release.
