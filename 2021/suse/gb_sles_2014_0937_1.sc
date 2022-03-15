if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0937.1" );
	script_cve_id( "CVE-2013-5211" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0937-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0937-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140937-1/" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2014-01/msg00005.html" );
	script_xref( name: "URL", value: "http://support.novell.com/security/cve/CVE-2013-5211.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2014:0937-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The NTP time service could have been used for remote denial of service amplification attacks.

This issue can be fixed by the administrator as we described in our security advisory SUSE-SA:2014:001:
[link moved to references]
>

and on

[link moved to references] This update now also replaces the default ntp.conf template to fix this problem.
Please note that if you have touched or modified ntp.conf yourself, it will not be automatically fixed, you need to merge the changes manually as described.
Additionally the following bug has been fixed:
 * ntp start script does not update the /var/lib/ntp/etc/localtime file
 if /etc/localtime is a symlink (bnc#838458)
Security Issues:
 * CVE-2013-5211" );
	script_tag( name: "affected", value: "'ntp' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.4p8~1.24.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-doc", rpm: "ntp-doc~4.2.4p8~1.24.1", rls: "SLES11.0SP3" ) )){
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

