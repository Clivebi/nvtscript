if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704468" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-9858" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-17 00:29:00 +0000 (Mon, 17 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-22 02:00:09 +0000 (Sat, 22 Jun 2019)" );
	script_name( "Debian Security Advisory DSA 4468-1 (php-horde-form - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4468.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4468-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-horde-form'
  package(s) announced via the DSA-4468-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A path traversal vulnerability due to an unsanitized POST parameter was
discovered in php-horde-form, a package providing form rendering,
validation, and other functionality for the Horde Application Framework.
An attacker can take advantage of this flaw for remote code execution." );
	script_tag( name: "affected", value: "'php-horde-form' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 2.0.15-1+deb9u1.

We recommend that you upgrade your php-horde-form packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-horde-form", ver: "2.0.15-1+deb9u1", rls: "DEB9" ) )){
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

