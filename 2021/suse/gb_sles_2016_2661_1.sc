if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2661.1" );
	script_cve_id( "CVE-2016-4912", "CVE-2016-7567" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-29 13:26:00 +0000 (Wed, 29 Apr 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2661-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2661-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162661-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openslp' package(s) announced via the SUSE-SU-2016:2661-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openslp fixes two security issues and two bugs.
The following vulnerabilities were fixed:
- CVE-2016-4912: A remote attacker could have crashed the server with a
 large number of packages (bsc#980722)
- CVE-2016-7567: A remote attacker could cause a memory corruption having
 unspecified impact (bsc#1001600)
The following bugfix changes are included:
- bsc#994989: Removed convenience code as changes bytes in the message
 buffer breaking the verification code
- bsc#974655: Removed no longer needed slpd init file" );
	script_tag( name: "affected", value: "'openslp' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "openslp", rpm: "openslp~2.0.0~17.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openslp-32bit", rpm: "openslp-32bit~2.0.0~17.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openslp-debuginfo", rpm: "openslp-debuginfo~2.0.0~17.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openslp-debuginfo-32bit", rpm: "openslp-debuginfo-32bit~2.0.0~17.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openslp-debugsource", rpm: "openslp-debugsource~2.0.0~17.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openslp-server", rpm: "openslp-server~2.0.0~17.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openslp-server-debuginfo", rpm: "openslp-server-debuginfo~2.0.0~17.1", rls: "SLES12.0SP1" ) )){
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

