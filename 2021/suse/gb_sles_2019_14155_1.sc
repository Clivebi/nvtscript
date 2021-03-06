if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.14155.1" );
	script_cve_id( "CVE-2019-3838" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:20 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 14:05:00 +0000 (Thu, 15 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:14155-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:14155-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-201914155-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghostscript-library' package(s) announced via the SUSE-SU-2019:14155-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ghostscript-library fixes the following issues:

Security issue fixed:
CVE-2019-3838: Fixed various bugs which allows to reenable and misuse
 system Postscript operators to read files from within Postscript files
 and send them with the help of e.g. the %pipe% to the attacker
 (bsc#1129186)." );
	script_tag( name: "affected", value: "'ghostscript-library' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-fonts-other", rpm: "ghostscript-fonts-other~8.62~47.16.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-fonts-rus", rpm: "ghostscript-fonts-rus~8.62~47.16.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-fonts-std", rpm: "ghostscript-fonts-std~8.62~47.16.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-library", rpm: "ghostscript-library~8.62~47.16.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-omni", rpm: "ghostscript-omni~8.62~47.16.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-x11", rpm: "ghostscript-x11~8.62~47.16.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgimpprint", rpm: "libgimpprint~4.2.7~47.16.1", rls: "SLES11.0SP4" ) )){
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

