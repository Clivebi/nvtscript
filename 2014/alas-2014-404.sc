if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120495" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:27:44 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-404)" );
	script_tag( name: "insight", value: "Multiple integer overflows in the (1) fs_get_reply, (2) fs_alloc_glyphs, and (3) fs_read_extent_info functions in X.Org libXfont before 1.4.8 and 1.4.9x before 1.4.99.901 allow remote font servers to execute arbitrary code via a crafted xfs reply, which triggers a buffer overflow.Multiple buffer overflows in X.Org libXfont before 1.4.8 and 1.4.9x before 1.4.99.901 allow remote font servers to execute arbitrary code via a crafted xfs protocol reply to the (1) _fs_recv_conn_setup, (2) fs_read_open_font, (3) fs_read_query_info, (4) fs_read_extent_info, (5) fs_read_glyphs, (6) fs_read_list, or (7) fs_read_list_info function.Multiple integer overflows in the (1) FontFileAddEntry and (2) lexAlias functions in X.Org libXfont before 1.4.8 and 1.4.9x before 1.4.99.901 might allow local users to gain privileges by adding a directory with a large fonts.dir or fonts.alias file to the font path, which triggers a heap-based buffer overflow, related to metadata." );
	script_tag( name: "solution", value: "Run yum update libXfont to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-404.html" );
	script_cve_id( "CVE-2014-0211", "CVE-2014-0210", "CVE-2014-0209" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Amazon Linux Local Security Checks" );
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
if(release == "AMAZON"){
	if(!isnull( res = isrpmvuln( pkg: "libXfont", rpm: "libXfont~1.4.5~3.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libXfont-devel", rpm: "libXfont-devel~1.4.5~3.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libXfont-debuginfo", rpm: "libXfont-debuginfo~1.4.5~3.9.amzn1", rls: "AMAZON" ) )){
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

