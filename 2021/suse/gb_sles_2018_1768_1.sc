if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1768.1" );
	script_cve_id( "CVE-2015-4000" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:43 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1768-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1768-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181768-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nagios-nrpe' package(s) announced via the SUSE-SU-2018:1768-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nagios-nrpe fixes one issue.
This security issue was fixed:
- CVE-2015-4000: Prevent Logjam. The TLS protocol 1.2 and earlier, when a
 DHE_EXPORT ciphersuite is enabled on a server but not on a client, did
 not properly convey a DHE_EXPORT choice, which allowed man-in-the-middle
 attackers to conduct cipher-downgrade attacks by rewriting a ClientHello
 with DHE replaced by DHE_EXPORT and then rewriting a ServerHello with
 DHE_EXPORT replaced by DHE (bsc#938906)." );
	script_tag( name: "affected", value: "'nagios-nrpe' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "nagios-nrpe", rpm: "nagios-nrpe~2.12~24.4.10.3.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nagios-nrpe-doc", rpm: "nagios-nrpe-doc~2.12~24.4.10.3.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nagios-plugins-nrpe", rpm: "nagios-plugins-nrpe~2.12~24.4.10.3.3", rls: "SLES11.0SP4" ) )){
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

