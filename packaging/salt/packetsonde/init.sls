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

{% for b in ['packetsonded', 'packetsonde-priv'] %}
packetsonded-bin-{{ b }}:
  file.managed:
    - name: /usr/local/sbin/{{ b }}
    - source: salt://packetsonde/bin/{{ b }}
    - mode: '0755'
{% endfor %}

packetsonde-cli-bin:
  file.managed:
    - name: /usr/local/bin/packetsonde
    - source: salt://packetsonde/bin/packetsonde
    - mode: '0755'

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
