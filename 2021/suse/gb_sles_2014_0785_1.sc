if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0785.1" );
	script_cve_id( "CVE-2013-6456", "CVE-2014-0179" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:20 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:S/C:N/I:P/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2015-01-03 02:22:00 +0000 (Sat, 03 Jan 2015)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0785-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0785-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140785-1/" );
	script_xref( name: "URL", value: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0179" );
	script_xref( name: "URL", value: "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-6456" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt' package(s) announced via the SUSE-SU-2014:0785-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libvirt has been patched to fix two security issues.

Further information is available at [link moved to references] and [link moved to references] These security issues have been fixed:
 * Unsafe parsing of XML documents allows arbitrary file read or denial
 of service (CVE-2014-0179)
 * Ability to delete or create arbitrary host devices (CVE-2013-6456)
Security Issue references:
 * CVE-2014-0179
 * CVE-2013-6456" );
	script_tag( name: "affected", value: "'libvirt' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libvirt", rpm: "libvirt~1.0.5.9~0.9.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client", rpm: "libvirt-client~1.0.5.9~0.9.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client-32bit", rpm: "libvirt-client-32bit~1.0.5.9~0.9.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-doc", rpm: "libvirt-doc~1.0.5.9~0.9.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-lock-sanlock", rpm: "libvirt-lock-sanlock~1.0.5.9~0.9.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-python", rpm: "libvirt-python~1.0.5.9~0.9.1", rls: "SLES11.0SP3" ) )){
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

