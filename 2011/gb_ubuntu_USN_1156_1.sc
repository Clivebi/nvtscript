if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1156-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840689" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-06-24 16:46:35 +0200 (Fri, 24 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "USN", value: "1156-1" );
	script_cve_id( "CVE-2010-2221", "CVE-2011-0001" );
	script_name( "Ubuntu Update for tgt USN-1156-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1156-1" );
	script_tag( name: "affected", value: "tgt on Ubuntu 11.04,
  Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that tgt incorrectly handled long iSCSI name strings, and
  invalid PDUs. A remote attacker could exploit this to cause tgt to crash,
  resulting in a denial of service, or possibly execute arbitrary code. This
  issue only affected Ubuntu 10.10. (CVE-2010-2221)

  Emmanuel Bouillon discovered that tgt incorrectly handled certain iSCSI
  logins. A remote attacker could exploit this to cause tgt to crash,
  resulting in a denial of service, or possibly execute arbitrary code.
  (CVE-2011-0001)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "tgt", ver: "1:1.0.4-1ubuntu4.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "tgt", ver: "1:1.0.13-0ubuntu2.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

