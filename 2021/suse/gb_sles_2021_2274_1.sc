if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2274.1" );
	script_cve_id( "CVE-2021-20286" );
	script_tag( name: "creation_date", value: "2021-07-09 11:37:50 +0000 (Fri, 09 Jul 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-22 14:32:00 +0000 (Mon, 22 Mar 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2274-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2|SLES15\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2274-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212274-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kubevirt' package(s) announced via the SUSE-SU-2021:2274-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for kubevirt fixes the following issues:

General:

Updated kubevirt to version 0.40.0

Fixed an issue when calling `virsh-domcapabilities`

Fixed the wrong registry path for containers.

Security fixes:

CVE-2021-20286: A flaw was found in libnbd 1.7.3. An assertion failure
 in nbd_unlocked_opt_go in ilb/opt.c may lead to denial of service." );
	script_tag( name: "affected", value: "'kubevirt' package(s) on SUSE Linux Enterprise Module for Containers 15-SP2, SUSE Linux Enterprise Module for Containers 15-SP3." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "kubevirt-virtctl", rpm: "kubevirt-virtctl~0.40.0~5.11.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubevirt-virtctl-debuginfo", rpm: "kubevirt-virtctl-debuginfo~0.40.0~5.11.2", rls: "SLES15.0SP2" ) )){
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
if(release == "SLES15.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kubevirt-virtctl", rpm: "kubevirt-virtctl~0.40.0~5.11.2", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kubevirt-virtctl-debuginfo", rpm: "kubevirt-virtctl-debuginfo~0.40.0~5.11.2", rls: "SLES15.0SP3" ) )){
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

