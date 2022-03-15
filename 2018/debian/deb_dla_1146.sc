if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891146" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2017-9868" );
	script_name( "Debian LTS: Security Advisory for mosquitto (DLA-1146-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-12 16:14:00 +0000 (Tue, 12 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/10/msg00023.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "mosquitto on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.15-2+deb7u2.

We recommend that you upgrade your mosquitto packages." );
	script_tag( name: "summary", value: "mosquitto's persistence file (mosquitto.db) was created in a
world-readable way thus allowing local users to obtain sensitive MQTT
topic information. While the application has been fixed to set
proper permissions by default, you still have to manually fix
the permissions on any existing file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmosquitto0", ver: "0.15-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmosquitto0-dev", ver: "0.15-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmosquittopp0", ver: "0.15-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmosquittopp0-dev", ver: "0.15-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mosquitto", ver: "0.15-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mosquitto-clients", ver: "0.15-2+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-mosquitto", ver: "0.15-2+deb7u2", rls: "DEB7" ) )){
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

