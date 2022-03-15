if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0111.2" );
	script_cve_id( "CVE-2019-5068" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:00 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-01 13:15:00 +0000 (Mon, 01 Jun 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0111-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0111-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200111-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Mesa' package(s) announced via the SUSE-SU-2020:0111-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for Mesa fixes the following issues:

Security issue fixed:

CVE-2019-5068: Fixed exploitable shared memory permissions vulnerability
 (bsc#1156015)." );
	script_tag( name: "affected", value: "'Mesa' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "Mesa-debugsource", rpm: "Mesa-debugsource~18.3.2~34.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libOSMesa8-32bit", rpm: "libOSMesa8-32bit~18.3.2~34.9.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libOSMesa8-32bit-debuginfo", rpm: "libOSMesa8-32bit-debuginfo~18.3.2~34.9.1", rls: "SLES15.0SP1" ) )){
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

