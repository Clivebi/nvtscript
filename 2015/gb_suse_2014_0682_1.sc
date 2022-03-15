if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850793" );
	script_version( "2020-06-03T08:38:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-03 08:38:58 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-10-13 18:35:00 +0530 (Tue, 13 Oct 2015)" );
	script_cve_id( "CVE-2014-2913" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for nagios-nrpe (SUSE-SU-2014:0682-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nagios-nrpe'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "nagios-nrpe has been updated to prevent possible remote command execution
  when command arguments are enabled. This issue affects versions 2.15 and
  older.

  These security issues have been fixed:

  * Remote command execution (CVE-2014-2913)" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Apr/240" );
	script_tag( name: "affected", value: "nagios-nrpe, on SUSE Linux Enterprise Server 11 SP3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2014:0682-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLES11\\.0SP3" );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "nagios-nrpe", rpm: "nagios-nrpe~2.12~24.4.10.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nagios-nrpe-doc", rpm: "nagios-nrpe-doc~2.12~24.4.10.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nagios-plugins-nrpe", rpm: "nagios-plugins-nrpe~2.12~24.4.10.1", rls: "SLES11.0SP3" ) )){
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

