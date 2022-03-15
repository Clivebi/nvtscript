if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1072.1" );
	script_cve_id( "CVE-2014-10070", "CVE-2014-10071", "CVE-2014-10072", "CVE-2016-10714", "CVE-2017-18205", "CVE-2017-18206", "CVE-2018-1071", "CVE-2018-1083", "CVE-2018-7549" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-11 19:27:00 +0000 (Tue, 11 Jun 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1072-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1072-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181072-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'zsh' package(s) announced via the SUSE-SU-2018:1072-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for zsh fixes the following issues:
 - CVE-2014-10070: environment variable injection could lead to local
 privilege escalation (bnc#1082885)
 - CVE-2014-10071: buffer overflow in exec.c could lead to denial of
 service. (bnc#1082977)
 - CVE-2014-10072: buffer overflow In utils.c when scanning very long
 directory paths for symbolic links. (bnc#1082975)
 - CVE-2016-10714: In zsh before 5.3, an off-by-one error resulted in
 undersized buffers that were intended to support PATH_MAX characters.
 (bnc#1083250)
 - CVE-2017-18205: In builtin.c when sh compatibility mode is used, a
 NULL pointer dereference could lead to denial of service (bnc#1082998)
 - CVE-2018-1071: exec.c:hashcmd() function vulnerability could lead to
 denial of service. (bnc#1084656)
 - CVE-2018-1083: Autocomplete vulnerability could lead to privilege
 escalation. (bnc#1087026)
 - CVE-2018-7549: In params.c in zsh through 5.4.2, there is a crash
 during a copy of an empty hash table, as demonstrated by typeset -p.
 (bnc#1082991)
 - CVE-2017-18206: buffer overrun in xsymlinks could lead to denial of
 service (bnc#1083002)
 - Autocomplete and REPORTTIME broken (bsc#896914)" );
	script_tag( name: "affected", value: "'zsh' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "zsh", rpm: "zsh~5.0.5~6.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zsh-debuginfo", rpm: "zsh-debuginfo~5.0.5~6.7.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zsh-debugsource", rpm: "zsh-debugsource~5.0.5~6.7.2", rls: "SLES12.0SP3" ) )){
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

