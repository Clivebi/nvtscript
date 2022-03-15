if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878834" );
	script_version( "2021-08-23T12:01:00+0000" );
	script_cve_id( "CVE-2020-26262" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 12:01:00 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 03:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-20 04:02:03 +0000 (Wed, 20 Jan 2021)" );
	script_name( "Fedora: Security Advisory for coturn (FEDORA-2021-dee141fc61)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2021-dee141fc61" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/G54UIUFTEC6RLPOISMB6FUW7456SBZC4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'coturn'
  package(s) announced via the FEDORA-2021-dee141fc61 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Coturn TURN Server is a VoIP media traffic NAT traversal server and gateway.
It can be used as a general-purpose network traffic TURN server/gateway, too.

This implementation also includes some extra features. Supported RFCs:

TURN specs:

  - RFC 5766 - base TURN specs

  - RFC 6062 - TCP relaying TURN extension

  - RFC 6156 - IPv6 extension for TURN

  - Experimental DTLS support as client protocol.

STUN specs:

  - RFC 3489 - 'classic' STUN

  - RFC 5389 - base 'new' STUN specs

  - RFC 5769 - test vectors for STUN protocol testing

  - RFC 5780 - NAT behavior discovery support

The implementation fully supports the following client-to-TURN-server protocols:

  - UDP (per RFC 5766)

  - TCP (per RFC 5766 and RFC 6062)

  - TLS (per RFC 5766 and RFC 6062), TLS1.0/TLS1.1/TLS1.2

  - DTLS (experimental non-standard feature)

Supported relay protocols:

  - UDP (per RFC 5766)

  - TCP (per RFC 6062)

Supported user databases (for user repository, with passwords or keys, if
authentication is required):

  - SQLite

  - MySQL

  - PostgreSQL

  - Redis

Redis can also be used for status and statistics storage and notification.

Supported TURN authentication mechanisms:

  - long-term

  - TURN REST API (a modification of the long-term mechanism, for time-limited
  secret-based authentication, for WebRTC applications)

The load balancing can be implemented with the following tools (either one or a
combination of them):

  - network load-balancer server

  - DNS-based load balancing

  - built-in ALTERNATE-SERVER mechanism." );
	script_tag( name: "affected", value: "'coturn' package(s) on Fedora 33." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "coturn", rpm: "coturn~4.5.2~1.fc33", rls: "FC33" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

