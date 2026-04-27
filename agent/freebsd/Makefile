PORTNAME=       packetsonde-agent
PORTVERSION=    0.1.0
CATEGORIES=     net
MASTER_SITES=   # local build

MAINTAINER=     bill@billn.net
COMMENT=        Passive network sensor with honeypot and flow generation

LICENSE=        MIT

BUILD_DEPENDS=  cmake:devel/cmake
LIB_DEPENDS=    libpcap.so:net/libpcap

USES=           cmake ssl

CMAKE_ARGS=     -DCMAKE_INSTALL_PREFIX=${PREFIX} \
                -DSYSCONFDIR=${PREFIX}/etc

OPTIONS_DEFINE= REDIS
OPTIONS_DEFAULT= REDIS
REDIS_LIB_DEPENDS= libhiredis.so:databases/hiredis
REDIS_CMAKE_BOOL= WITH_REDIS

post-install:
	@${MKDIR} ${STAGEDIR}${PREFIX}/etc/packetsonde
	${INSTALL_DATA} ${WRKSRC}/conf/packetsonde.conf.default \
		${STAGEDIR}${PREFIX}/etc/packetsonde/packetsonde.conf.example
	${INSTALL_DATA} ${WRKSRC}/conf/honeypot.conf.example \
		${STAGEDIR}${PREFIX}/etc/packetsonde/honeypot.conf.example
	${INSTALL_SCRIPT} ${WRKSRC}/scripts/packetsonde-agent.rc \
		${STAGEDIR}${PREFIX}/etc/rc.d/packetsonde-agent

.include <bsd.port.mk>
