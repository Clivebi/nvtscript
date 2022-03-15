if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891507" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2011-2767" );
	script_name( "Debian LTS: Security Advisory for libapache2-mod-perl2 (DLA-1507-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-19 00:00:00 +0200 (Wed, 19 Sep 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-24 18:15:00 +0000 (Tue, 24 Sep 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/09/msg00018.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libapache2-mod-perl2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.0.9~1624218-2+deb8u3.

We recommend that you upgrade your libapache2-mod-perl2 packages." );
	script_tag( name: "summary", value: "Jan Ingvoldstad discovered that libapache2-mod-perl2 allows attackers to
execute arbitrary Perl code by placing it in a user-owned .htaccess
file, because (contrary to the documentation) there is no configuration
option that permits Perl code for the administrator's control of HTTP
request processing without also permitting unprivileged users to run
Perl code in the context of the user account that runs Apache HTTP
Server processes." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-perl2", ver: "2.0.9~1624218-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-perl2-dev", ver: "2.0.9~1624218-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-perl2-doc", ver: "2.0.9~1624218-2+deb8u3", rls: "DEB8" ) )){
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

