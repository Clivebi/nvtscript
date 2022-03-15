if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:175" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831752" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-12-04 09:49:35 +0530 (Tue, 04 Dec 2012)" );
	script_cve_id( "CVE-2012-4559", "CVE-2012-4560", "CVE-2012-4561", "CVE-2012-4562" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2012:175" );
	script_name( "Mandriva Update for libssh MDVSA-2012:175 (libssh)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libssh'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_2011\\.0" );
	script_tag( name: "affected", value: "libssh on Mandriva Linux 2011.0" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Multiple double free(), buffer overflow, invalid free() and improper
  overflow checks vulnerabilities was found and corrected in libssh
  (CVE-2012-4559, CVE-2012-4560, CVE-2012-4561, CVE-2012-4562).

  The updated packages have been upgraded to the 0.5.3 version which
  is not affected by these issues." );
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
	if(( res = isrpmvuln( pkg: "libssh4", rpm: "libssh4~0.5.3~0.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libssh-devel", rpm: "libssh-devel~0.5.3~0.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64ssh4", rpm: "lib64ssh4~0.5.3~0.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64ssh-devel", rpm: "lib64ssh-devel~0.5.3~0.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

