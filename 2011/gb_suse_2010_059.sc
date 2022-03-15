if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850152" );
	script_version( "2020-01-31T08:40:24+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:40:24 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2011-01-04 09:11:34 +0100 (Tue, 04 Jan 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "SUSE-SA", value: "2010-059" );
	script_cve_id( "CVE-2010-4344", "CVE-2010-4345" );
	script_name( "SUSE: Security Advisory for exim (SUSE-SA:2010:059)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exim'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE11\\.1|openSUSE11\\.2)" );
	script_tag( name: "impact", value: "remote code execution" );
	script_tag( name: "affected", value: "exim on openSUSE 11.1, openSUSE 11.2" );
	script_tag( name: "insight", value: "The unprivileged user exim is running as could tell the exim daemon
  to read a different config file and leverage that to escalate
  privileges to root CVE-2010-4345.

  A buffer overflow in exim allowed remote attackers to execute
  arbitrary code CVE-2010-4344. openSUSE 11.3 is not affected by
  this flaw." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
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
report = "";
if(release == "openSUSE11.1"){
	if(!isnull( res = isrpmvuln( pkg: "exim", rpm: "exim~4.69~70.15.1", rls: "openSUSE11.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximon", rpm: "eximon~4.69~70.15.1", rls: "openSUSE11.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximstats-html", rpm: "eximstats-html~4.69~70.15.1", rls: "openSUSE11.1" ) )){
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
if(release == "openSUSE11.2"){
	if(!isnull( res = isrpmvuln( pkg: "exim", rpm: "exim~4.69~72.6.1", rls: "openSUSE11.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximon", rpm: "eximon~4.69~72.6.1", rls: "openSUSE11.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximstats-html", rpm: "eximstats-html~4.69~72.6.1", rls: "openSUSE11.2" ) )){
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

