if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:155-1" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831736" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-10-03 09:25:23 +0530 (Wed, 03 Oct 2012)" );
	script_cve_id( "CVE-2012-0862" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_xref( name: "MDVSA", value: "2012:155-1" );
	script_name( "Mandriva Update for xinetd MDVSA-2012:155-1 (xinetd)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xinetd'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_2011\\.0" );
	script_tag( name: "affected", value: "xinetd on Mandriva Linux 2011.0" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A security issue was identified and fixed in xinetd:

  builtins.c in Xinetd before 2.3.15 does not check the service type
  when the tcpmux-server service is enabled, which exposes all enabled
  services and allows remote attackers to bypass intended access
  restrictions via a request to tcpmux port 1 (CVE-2012-0862).

  The updated packages have been patched to correct this issue." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MNDK_2011.0"){
	if(( res = isrpmvuln( pkg: "xinetd", rpm: "xinetd~2.3.14~13.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xinetd-simple-services", rpm: "xinetd-simple-services~2.3.14~13.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

