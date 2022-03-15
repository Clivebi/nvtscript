if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.0114.1" );
	script_cve_id( "CVE-2015-2296" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-18 13:19:00 +0000 (Thu, 18 Mar 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:0114-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:0114-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20160114-1/" );
	script_xref( name: "URL", value: "http://docs.python-requests.org/en/latest/community/updates/#id3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-requests' package(s) announced via the SUSE-SU-2016:0114-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The python-requests module has been updated to version 2.8.1, which brings several fixes and enhancements:
- Fix handling of cookies on redirect. Previously a cookie without a host
 value set would use the hostname for the redirected URL exposing
 requests users to session fixation attacks and potentially cookie
 stealing. (bsc#922448, CVE-2015-2296)
- Add support for per-host proxies. This allows the proxies dictionary to
 have entries
 of the form {'://': ''}. Host-specific proxies
 will be used in preference to the previously-supported scheme-specific
 ones, but the previous syntax will continue to work.
- Update certificate bundle to match 'certifi' 2015.9.6.2's weak
 certificate bundle.
- Response.raise_for_status now prints the URL that failed as part of the
 exception message.
- requests.utils.get_netrc_auth now takes an raise_errors kwarg,
 defaulting to False. When True, errors parsing .netrc files cause
 exceptions to be thrown.
- Change to bundled projects import logic to make it easier to unbundle
 requests downstream.
- Change the default User-Agent string to avoid leaking data on Linux: now
 contains only the requests version.
- The json parameter to post() and friends will now only be used if
 neither data nor files are present, consistent with the documentation.
- Empty fields in the NO_PROXY environment variable are now ignored.
- Fix problem where httplib.BadStatusLine would get raised if combining
 stream=True with contextlib.closing.
- Prevent bugs where we would attempt to return the same connection back
 to the connection pool twice when sending a Chunked body.
- Digest Auth support is now thread safe.
- Resolved several bugs involving chunked transfer encoding and response
 framing.
- Copy a PreparedRequest's CookieJar more reliably.
- Support bytearrays when passed as parameters in the 'files' argument.
- Avoid data duplication when creating a request with 'str', 'bytes', or
 'bytearray' input to the 'files' argument.
- 'Connection: keep-alive' header is now sent automatically.
- Support for connect timeouts. Timeout now accepts a tuple (connect,
 read) which is used to set individual connect and read timeouts.
For a comprehensive list of changes please refer to the package's change log or the Release Notes at [link moved to references]" );
	script_tag( name: "affected", value: "'python-requests' package(s) on SUSE Enterprise Storage 1.0, SUSE Enterprise Storage 2, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise High Availability 12, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE OpenStack Cloud Compute 5." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "python-requests", rpm: "python-requests~2.8.1~6.9.1", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "python-requests", rpm: "python-requests~2.8.1~6.9.1", rls: "SLES12.0SP1" ) )){
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

