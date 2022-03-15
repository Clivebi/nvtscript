if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0890.1" );
	script_cve_id( "CVE-2021-27218", "CVE-2021-27219" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-07 10:15:00 +0000 (Wed, 07 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0890-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0890-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210890-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glib2' package(s) announced via the SUSE-SU-2021:0890-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for glib2 fixes the following issues:

CVE-2021-27218: g_byte_array_new_take takes a gsize as length but stores
 in a guint, this patch will refuse if the length is larger than guint.
 (bsc#1182328)

CVE-2021-27219: g_memdup takes a guint as parameter and sometimes leads
 into an integer overflow, so add a g_memdup2 function which uses gsize
 to replace it. (bsc#1182362)" );
	script_tag( name: "affected", value: "'glib2' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "glib2-debugsource", rpm: "glib2-debugsource~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-devel", rpm: "glib2-devel~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-devel-debuginfo", rpm: "glib2-devel-debuginfo~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-lang", rpm: "glib2-lang~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools", rpm: "glib2-tools~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools-debuginfo", rpm: "glib2-tools-debuginfo~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0", rpm: "libgio-2_0-0~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-debuginfo", rpm: "libgio-2_0-0-debuginfo~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0", rpm: "libglib-2_0-0~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-debuginfo", rpm: "libglib-2_0-0-debuginfo~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0", rpm: "libgmodule-2_0-0~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-debuginfo", rpm: "libgmodule-2_0-0-debuginfo~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0", rpm: "libgobject-2_0-0~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-debuginfo", rpm: "libgobject-2_0-0-debuginfo~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0", rpm: "libgthread-2_0-0~2.54.3~4.24.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-debuginfo", rpm: "libgthread-2_0-0-debuginfo~2.54.3~4.24.1", rls: "SLES15.0" ) )){
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "glib2-debugsource", rpm: "glib2-debugsource~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-devel", rpm: "glib2-devel~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-devel-debuginfo", rpm: "glib2-devel-debuginfo~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-lang", rpm: "glib2-lang~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools", rpm: "glib2-tools~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools-debuginfo", rpm: "glib2-tools-debuginfo~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0", rpm: "libgio-2_0-0~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-32bit", rpm: "libgio-2_0-0-32bit~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-32bit-debuginfo", rpm: "libgio-2_0-0-32bit-debuginfo~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-debuginfo", rpm: "libgio-2_0-0-debuginfo~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0", rpm: "libglib-2_0-0~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-32bit", rpm: "libglib-2_0-0-32bit~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-32bit-debuginfo", rpm: "libglib-2_0-0-32bit-debuginfo~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-debuginfo", rpm: "libglib-2_0-0-debuginfo~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0", rpm: "libgmodule-2_0-0~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-32bit", rpm: "libgmodule-2_0-0-32bit~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-32bit-debuginfo", rpm: "libgmodule-2_0-0-32bit-debuginfo~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-debuginfo", rpm: "libgmodule-2_0-0-debuginfo~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0", rpm: "libgobject-2_0-0~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-32bit", rpm: "libgobject-2_0-0-32bit~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-32bit-debuginfo", rpm: "libgobject-2_0-0-32bit-debuginfo~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-debuginfo", rpm: "libgobject-2_0-0-debuginfo~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0", rpm: "libgthread-2_0-0~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-debuginfo", rpm: "libgthread-2_0-0-debuginfo~2.54.3~4.24.1", rls: "SLES15.0SP1" ) )){
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

