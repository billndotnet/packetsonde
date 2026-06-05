# packetsonde agent: install from the salt fileserver + enroll with central.
# agent_id = minion id. Enrollment lands `pending`; an engineer validates it.
# Apply per-minion: `salt '<minion>' state.apply packetsonde`.

{% set central_url = salt['pillar.get']('packetsonde:central_url', '') %}

packetsonded-user:
  user.present:
    - name: packetsonded
    - system: True
    - createhome: False
    - shell: /usr/sbin/nologin

# Runtime shared-library dependencies of the binaries. packetsonde-priv links
# libpcap (passive capture); packetsonded links libhiredis (Redis bridge) +
# OpenSSL; the CLI links libedit + OpenSSL. A host missing libpcap crash-loops
# the priv worker (broken pipe) and captures nothing — install before the
# binaries run. Package names below are Ubuntu 24.04 / noble (post-t64);
# adjust per distro (e.g. libpcap0.8 / libssl3 on pre-t64 / non-Ubuntu).
packetsonded-deps:
  pkg.installed:
    - pkgs:
      - libpcap0.8t64
      - libhiredis1.1.0
      - libssl3t64
      - libedit2

{% for b in ['packetsonded', 'packetsonde-priv'] %}
packetsonded-bin-{{ b }}:
  file.managed:
    - name: /usr/local/sbin/{{ b }}
    - source: salt://packetsonde/bin/{{ b }}
    - mode: '0755'
    - require:
      - pkg: packetsonded-deps
{% endfor %}

packetsonde-cli-bin:
  file.managed:
    - name: /usr/local/bin/packetsonde
    - source: salt://packetsonde/bin/packetsonde
    - mode: '0755'
    - require:
      - pkg: packetsonded-deps

packetsonded-unit:
  file.managed:
    - name: /etc/systemd/system/packetsonded.service
    - source: salt://packetsonde/packetsonded.service
    - mode: '0644'
  module.run:
    - name: service.systemctl_reload
    - onchanges:
      - file: packetsonded-unit

packetsonded-keydir:
  file.directory:
    - name: /etc/packetsonded/keys/authorized
    - user: packetsonded
    - group: packetsonded
    - mode: '0750'
    - makedirs: True
    - require:
      - user: packetsonded-user

packetsonded-config:
  file.managed:
    - name: /etc/packetsonded/packetsonded.toml
    - source: salt://packetsonde/packetsonded.toml.jinja
    - template: jinja
    - user: packetsonded
    - group: packetsonded
    - mode: '0640'
    - require:
      - file: packetsonded-keydir

{% if central_url %}
packetsonde-register:
  cmd.run:
    - name: packetsonde register --config /etc/packetsonded/packetsonded.toml --provenance salt && touch /etc/packetsonded/registered
    - runas: packetsonded
    - unless: test -f /etc/packetsonded/registered
    - require:
      - file: packetsonded-config
      - file: packetsonde-cli-bin
{% endif %}

packetsonded-service:
  service.running:
    - name: packetsonded
    - enable: True
    - watch:
      - file: packetsonded-config
      - file: packetsonded-unit
      - file: packetsonded-bin-packetsonded
    - require:
      - file: packetsonded-bin-packetsonded
      - file: packetsonded-bin-packetsonde-priv
      - file: packetsonded-config
