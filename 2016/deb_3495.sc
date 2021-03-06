if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703495" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-2054", "CVE-2016-2055", "CVE-2016-2056", "CVE-2016-2057", "CVE-2016-2058" );
	script_name( "Debian Security Advisory DSA 3495-1 (xymon - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-08 12:37:37 +0530 (Tue, 08 Mar 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3495.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "xymon on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 4.3.17-6+deb8u1.

We recommend that you upgrade your xymon packages." );
	script_tag( name: "summary", value: "Markus Krell discovered that xymon, a network- and
applications-monitoring system, was vulnerable to the following
security issues:

CVE-2016-2054The incorrect handling of user-supplied input in the config

command can trigger a stack-based buffer overflow, resulting in
denial of service (via application crash) or remote code execution.

CVE-2016-2055The incorrect handling of user-supplied input in the config

command can lead to an information leak by serving sensitive
configuration files to a remote user.

CVE-2016-2056
The commands handling password management do not properly validate
user-supplied input, and are thus vulnerable to shell command
injection by a remote user.

CVE-2016-2057
Incorrect permissions on an internal queuing system allow a user
with a local account on the xymon master server to bypass all
network-based access control lists, and thus inject messages
directly into xymon.

CVE-2016-2058
Incorrect escaping of user-supplied input in status webpages can
be used to trigger reflected cross-site scripting attacks." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "xymon", ver: "4.3.17-6+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xymon-client", ver: "4.3.17-6+deb8u1", rls: "DEB8" ) ) != NULL){
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

