if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704373" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2018-4056", "CVE-2018-4058", "CVE-2018-4059" );
	script_name( "Debian Security Advisory DSA 4373-1 (coturn - security update)" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-28 00:00:00 +0100 (Mon, 28 Jan 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-27 16:22:00 +0000 (Wed, 27 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4373.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "coturn on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 4.5.0.5-1+deb9u1.

We recommend that you upgrade your coturn packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/coturn" );
	script_tag( name: "summary", value: "Multiple vulnerabilities were discovered in coTURN, a TURN and STUN server for
VoIP.

CVE-2018-4056
An SQL injection vulnerability was discovered in the coTURN administrator
web portal. As the administration web interface is shared with the
production, it is unfortunately not possible to easily filter outside
access and this security update completely disable the web interface. Users
should use the local, command line interface instead.

CVE-2018-4058
Default configuration enables unsafe loopback forwarding. A remote attacker
with access to the TURN interface can use this vulnerability to gain access
to services that should be local only.

CVE-2018-4059Default configuration uses an empty password for the local command line
administration interface. An attacker with access to the local console
(either a local attacker or a remote attacker taking advantage of
CVE-2018-4058
)
could escalade privileges to administrator of the coTURN
server." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "coturn", ver: "4.5.0.5-1+deb9u1", rls: "DEB9" ) )){
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

