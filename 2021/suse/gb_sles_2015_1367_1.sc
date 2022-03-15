if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1367.1" );
	script_cve_id( "CVE-2015-4047" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:11 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-27 18:04:00 +0000 (Wed, 27 Mar 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1367-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3|SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1367-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151367-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ipsec-tools' package(s) announced via the SUSE-SU-2015:1367-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ipsec-tools was updated to fix one security issue and a bug.
This security issue was fixed:
- CVE-2015-4047: racoon/gssapi.c in ipsec-tools allowed remote attackers
 to cause a denial of service (NULL pointer dereference and IKE daemon
 crash) via a series of crafted UDP requests (bsc#931989).
Due to a packaging error, the racoonf.conf config file was symlinked to
/usr/share/doc/packages/ipsec-tools/examples/racoon/samples/racoon.conf on some processor platforms, edits might have happened only in this
 example file.
Before upgrading, please check if /etc/racoon/racoon.conf is a symlink to this example file and backup the content. (bsc#939810)" );
	script_tag( name: "affected", value: "'ipsec-tools' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for VMWare 11-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "ipsec-tools", rpm: "ipsec-tools~0.7.3~1.13.1", rls: "SLES11.0SP3" ) )){
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "ipsec-tools", rpm: "ipsec-tools~0.7.3~1.13.1", rls: "SLES11.0SP4" ) )){
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

