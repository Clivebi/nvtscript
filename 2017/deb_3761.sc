if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703761" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_cve_id( "CVE-2016-9877" );
	script_name( "Debian Security Advisory DSA 3761-1 (rabbitmq-server - security update)" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-13 00:00:00 +0100 (Fri, 13 Jan 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-21 10:29:00 +0000 (Fri, 21 Sep 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3761.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "rabbitmq-server on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 3.3.5-1.1+deb8u1.

For the testing (stretch) and unstable (sid) distributions, this
problem has been fixed in version 3.6.6-1.

We recommend that you upgrade your rabbitmq-server packages." );
	script_tag( name: "summary", value: "It was discovered that RabbitMQ, an
implementation of the AMQP protocol, didn't correctly validate MQTT (MQ Telemetry
Transport) connection authentication. This allowed anyone to login to an existing
user account without having to provide a password." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "rabbitmq-server", ver: "3.3.5-1.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rabbitmq-server", ver: "3.6.6-1", rls: "DEB9" ) ) != NULL){
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

