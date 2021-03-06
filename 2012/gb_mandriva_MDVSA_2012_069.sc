if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:069" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831567" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-03 09:49:37 +0530 (Fri, 03 Aug 2012)" );
	script_cve_id( "CVE-2012-1586" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_xref( name: "MDVSA", value: "2012:069" );
	script_name( "Mandriva Update for cifs-utils MDVSA-2012:069 (cifs-utils)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cifs-utils'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2011\\.0|2010\\.1)" );
	script_tag( name: "affected", value: "cifs-utils on Mandriva Linux 2011.0,
  Mandriva Linux 2010.1" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A vulnerability has been found and corrected in cifs-utils:

  A file existence dislosure flaw was found in the way mount.cifs tool
  of the Samba SMB/CIFS tools suite performed mount of a Linux CIFS
  (Common Internet File System) filesystem. A local user, able to
  mount a remote CIFS share / target to a local directory could use
  this flaw to confirm (non) existence of a file system object (file,
  directory or process descriptor) via error messages generated during
  the mount.cifs tool run (CVE-2012-1586).

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
	if(( res = isrpmvuln( pkg: "cifs-utils", rpm: "cifs-utils~4.9~1.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "cifs-utils", rpm: "cifs-utils~4.8.1~0.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

