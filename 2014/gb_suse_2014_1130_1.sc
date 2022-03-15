if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850611" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2014-09-16 06:01:49 +0200 (Tue, 16 Sep 2014)" );
	script_cve_id( "CVE-2014-0547", "CVE-2014-0548", "CVE-2014-0549", "CVE-2014-0550", "CVE-2014-0551", "CVE-2014-0552", "CVE-2014-0553", "CVE-2014-0554", "CVE-2014-0555", "CVE-2014-0556", "CVE-2014-0557", "CVE-2014-0559" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "openSUSE: Security Advisory for update (openSUSE-SU-2014:1130-1)" );
	script_tag( name: "insight", value: "Adobe Flash Player was updated to 11.2.202.406 (bnc#895856):

  * APSB14-21, CVE-2014-0547, CVE-2014-0548, CVE-2014-0549, CVE-2014-0550,
  CVE-2014-0551, CVE-2014-0552, CVE-2014-0553, CVE-2014-0554,
  CVE-2014-0555, CVE-2014-0556, CVE-2014-0557, CVE-2014-0559

  More information can be found on the referenced vendor advisory." );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/flash-player/apsb14-21.html" );
	script_tag( name: "affected", value: "update on openSUSE 11.4" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "openSUSE-SU", value: "2014:1130-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'update'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE11\\.4" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSE11.4"){
	if(!isnull( res = isrpmvuln( pkg: "flash-player", rpm: "flash-player~11.2.202.406~127.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "flash-player-gnome", rpm: "flash-player-gnome~11.2.202.406~127.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "flash-player-kde4", rpm: "flash-player-kde4~11.2.202.406~127.1", rls: "openSUSE11.4" ) )){
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
}
exit( 0 );

