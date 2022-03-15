if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0569.1" );
	script_cve_id( "CVE-2014-0128" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0569-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0569-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140569-1/" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2014_1.txt" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid3' package(s) announced via the SUSE-SU-2014:0569-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A remote DoS attack in the Squid web proxy has been fixed.

Due to incorrect state management, Squid was vulnerable to a denial of service attack when processing certain HTTPS requests (CVE-2014-0128).

For more information see [link moved to references] .
Additionally, a bug in the logrotate configuration file has been fixed. The 'su' statement was moved into the
'logfile' section (bnc#677335).
Security Issue reference:
 * CVE-2014-0128
>Special Instructions and Notes:
Please reboot the system after installing this update." );
	script_tag( name: "affected", value: "'squid3' package(s) on SUSE Linux Enterprise Server 11 SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "squid3", rpm: "squid3~3.1.12~8.16.18.1", rls: "SLES11.0SP3" ) )){
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

