if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891962" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2017-18638" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-21 16:15:00 +0000 (Mon, 21 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-10-22 02:00:43 +0000 (Tue, 22 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for graphite-web (DLA-1962-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00030.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1962-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'graphite-web'
  package(s) announced via the DLA-1962-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The 'send_email' function in graphite-web/webapp/graphite/composer/views.py
in Graphite is vulnerable to SSRF. The vulnerable SSRF endpoint can be used
by an attacker to have the Graphite web server request any resource.
The response to this SSRF request is encoded into an image file and then sent
to an e-mail address that can be supplied by the attacker. Thus, an attacker
can exfiltrate any information." );
	script_tag( name: "affected", value: "'graphite-web' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.9.12+debian-6+deb8u1.

We recommend that you upgrade your graphite-web packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "graphite-web", ver: "0.9.12+debian-6+deb8u1", rls: "DEB8" ) )){
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

