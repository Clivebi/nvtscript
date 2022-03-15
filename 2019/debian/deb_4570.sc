if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704570" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-11779" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-23 21:15:00 +0000 (Mon, 23 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-11-19 03:00:16 +0000 (Tue, 19 Nov 2019)" );
	script_name( "Debian Security Advisory DSA 4570-1 (mosquitto - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4570.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4570-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mosquitto'
  package(s) announced via the DSA-4570-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was discovered in mosquitto, a MQTT version 3.1/3.1.1
compatible message broker, allowing a malicious MQTT client to cause a
denial of service (stack overflow and daemon crash), by sending a
specially crafted SUBSCRIBE packet containing a topic with an extremely
deep hierarchy." );
	script_tag( name: "affected", value: "'mosquitto' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.5.7-1+deb10u1.

We recommend that you upgrade your mosquitto packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmosquitto-dev", ver: "1.5.7-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmosquitto1", ver: "1.5.7-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmosquittopp-dev", ver: "1.5.7-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmosquittopp1", ver: "1.5.7-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mosquitto", ver: "1.5.7-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mosquitto-clients", ver: "1.5.7-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mosquitto-dev", ver: "1.5.7-1+deb10u1", rls: "DEB10" ) )){
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

