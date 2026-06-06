# packetsonde agent: install from the salt fileserver + enroll with central.
# agent_id = minion id. Enrollment lands `pending`; an engineer validates it.
# Apply per-minion: `salt '<minion>' state.apply packetsonde`.
#
# Binaries are per-OS-family: the fileserver carries native builds under
# bin/<os_family>/ (Debian = Ubuntu x86-64, RedHat = Rocky 9, FreeBSD = 14).
# Service management is systemd on Linux, rc.d on FreeBSD.

{% set central_url = salt['pillar.get']('packetsonde:central_url', '') %}
{% set osf = grains['os_family'] %}

packetsonded-user:
  user.present:
    - name: packetsonded
    - system: True
    - createhome: False
    - shell: /usr/sbin/nologin

# Runtime shared-library dependencies of the binaries. packetsonde-priv links
# libpcap (passive capture); packetsonded links OpenSSL (+ optional hiredis);
# the CLI links libedit + OpenSSL. On FreeBSD every runtime lib ships in base
# (verified via ldd), so the list there is effectively a no-op.
packetsonded-deps:
  pkg.installed:
    - pkgs:
{%- if osf == 'Debian' %}
      - libpcap0.8t64
      - libhiredis1.1.0
      - libssl3t64
      - libedit2
{%- elif osf == 'RedHat' %}
      # hiredis omitted: the Rocky build links no Redis bridge, and the pkg
      # needs EPEL (would fail the deps install). ldd-verified set:
      - libpcap
      - openssl-libs
      - libedit
{%- elif osf == 'FreeBSD' %}
      # libpcap/OpenSSL/libedit/libthr all ship in FreeBSD base; the Redis
      # bridge lib is the only possible add-on (the stock build omits it).
      - hiredis
{%- else %}
      # Unknown OS family: install nothing and let the binaries' own runtime
      # link errors surface, rather than failing the whole state on a bad
      # package name. (Extend this block per new platform.)
{%- endif %}

{% for b in ['packetsonded', 'packetsonde-priv'] %}
packetsonded-bin-{{ b }}:
  file.managed:
    - name: /usr/local/sbin/{{ b }}
    - source: salt://packetsonde/bin/{{ osf }}/{{ b }}
    - mode: '0755'
    - require:
      - pkg: packetsonded-deps
{% endfor %}

packetsonde-cli-bin:
  file.managed:
    - name: /usr/local/bin/packetsonde
    - source: salt://packetsonde/bin/{{ osf }}/packetsonde
    - mode: '0755'
    - require:
      - pkg: packetsonded-deps

{% if osf == 'FreeBSD' %}
# FreeBSD: rc.d script (no systemd). daemon(8) supervises + restarts the
# foreground agent; it starts as root and drops the brain's privileges itself.
packetsonded-unit:
  file.managed:
    - name: /usr/local/etc/rc.d/packetsonded
    - source: salt://packetsonde/packetsonded.rc
    - mode: '0755'
{% else %}
packetsonded-unit:
  file.managed:
    - name: /etc/systemd/system/packetsonded.service
    - source: salt://packetsonde/packetsonded.service
    - mode: '0644'
  module.run:
    - name: service.systemctl_reload
    - onchanges:
      - file: packetsonded-unit
{% endif %}

packetsonded-keydir:
  file.directory:
    - name: /etc/packetsonded/keys/authorized
    - user: packetsonded
    - group: packetsonded
    - mode: '0750'
    - makedirs: True
    - require:
      - user: packetsonded-user

# State dir for the [detect] activity sink + learned baseline. The unprivileged
# agent only writes the sink if this directory already exists; create it
# unconditionally (cheap, empty unless [detect] is enabled).
packetsonded-statedir:
  file.directory:
    - name: /var/lib/packetsonde
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
    # Bound the enrollment HTTP call so a slow/unreachable central (or the
    # FreeBSD register-HTTP hang under investigation) can never wedge the
    # apply. On timeout the marker isn't written, so a later apply retries.
    - name: timeout 60 packetsonde register --config /etc/packetsonded/packetsonded.toml --provenance salt && touch /etc/packetsonded/registered
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
      - file: packetsonded-unit
      - file: packetsonded-config
      - file: packetsonded-statedir
