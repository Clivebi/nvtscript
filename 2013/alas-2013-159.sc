if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120239" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:21:11 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2013-159)" );
	script_tag( name: "insight", value: "GDB tried to auto-load certain files (such as GDB scripts, Python scripts, and a thread debugging library) from the current working directory when debugging programs. This could result in the execution of arbitrary code with the user's privileges when GDB was run in a directory that has untrusted content. (CVE-2011-4355 )With this update, GDB no longer auto-loads files from the current directory and only trusts certain system directories by default. The list of trusted directories can be viewed and modified using the show auto-load safe-path and set auto-load safe-path GDB commands. Refer to the GDB manual, linked to in the References, for further information." );
	script_tag( name: "solution", value: "Run yum update gdb to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2013-159.html" );
	script_cve_id( "CVE-2011-4355" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "gdb", rpm: "gdb~7.2~60.13.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdb-gdbserver", rpm: "gdb-gdbserver~7.2~60.13.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gdb-debuginfo", rpm: "gdb-debuginfo~7.2~60.13.amzn1", rls: "AMAZON" ) )){
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

