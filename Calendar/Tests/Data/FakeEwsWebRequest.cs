// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// In-memory replacement for HttpWebRequest used by the Calendar Pester tests. It is registered only for
// test host names below .invalid, records each request and returns queued responses.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace ExOPTests
{
    public class FakeEwsResponse
    {
        public int StatusCode;
        public string Content;
    }

    public static class FakeEwsServer
    {
        public static readonly Queue<FakeEwsResponse> Responses = new Queue<FakeEwsResponse>();
        public static readonly List<string> Requests = new List<string>();
        public static readonly List<string> Urls = new List<string>();
        public static ICredentials LastCredentials;
        public static bool LastUseDefaultCredentials;

        public static void Reset()
        {
            Responses.Clear();
            Requests.Clear();
            Urls.Clear();
            LastCredentials = null;
            LastUseDefaultCredentials = false;
        }

        public static void Enqueue(int statusCode, string content)
        {
            FakeEwsResponse response = new FakeEwsResponse();
            response.StatusCode = statusCode;
            response.Content = content;
            Responses.Enqueue(response);
        }
    }

    public class FakeEwsWebRequestCreator : IWebRequestCreate
    {
        public WebRequest Create(Uri uri) { return new FakeEwsWebRequest(uri); }
    }

    public class FakeEwsWebRequest : WebRequest
    {
        private readonly Uri uri;
        private readonly MemoryStream body = new MemoryStream();
        private WebHeaderCollection headers = new WebHeaderCollection();

        public FakeEwsWebRequest(Uri uri) { this.uri = uri; }
        public override Uri RequestUri { get { return uri; } }
        public override string Method { get; set; }
        public override string ContentType { get; set; }
        public override long ContentLength { get; set; }
        public override int Timeout { get; set; }
        public override string ConnectionGroupName { get; set; }
        public override WebHeaderCollection Headers { get { return headers; } set { headers = value; } }
        public override ICredentials Credentials { get; set; }
        public override bool UseDefaultCredentials { get; set; }
        public int ReadWriteTimeout { get; set; }
        public bool AllowAutoRedirect { get; set; }
        public bool KeepAlive { get; set; }
        public ServicePoint ServicePoint { get { return ServicePointManager.FindServicePoint(uri); } }
        public override Stream GetRequestStream() { return body; }

        public override WebResponse GetResponse()
        {
            FakeEwsServer.Urls.Add(uri.AbsoluteUri);
            FakeEwsServer.LastCredentials = Credentials;
            FakeEwsServer.LastUseDefaultCredentials = UseDefaultCredentials;
            FakeEwsServer.Requests.Add(Encoding.UTF8.GetString(body.ToArray()));
            if (FakeEwsServer.Responses.Count == 0) { throw new InvalidOperationException("No fake response is queued."); }
            FakeEwsResponse next = FakeEwsServer.Responses.Dequeue();
            FakeEwsWebResponse response = new FakeEwsWebResponse((HttpStatusCode)next.StatusCode, next.Content);
            if (next.StatusCode != 200) { throw new WebException("The remote server returned an error.", null, WebExceptionStatus.ProtocolError, response); }
            return response;
        }
    }

    public class FakeEwsWebResponse : WebResponse
    {
        private readonly byte[] content;
        private readonly WebHeaderCollection headers = new WebHeaderCollection();
        private readonly HttpStatusCode statusCode;

        public FakeEwsWebResponse(HttpStatusCode statusCode, string text)
        {
            this.statusCode = statusCode;
            content = Encoding.UTF8.GetBytes(text);
        }

        public HttpStatusCode StatusCode { get { return statusCode; } }
        public override WebHeaderCollection Headers { get { return headers; } }
        public override long ContentLength { get { return content.Length; } set { } }
        public override Stream GetResponseStream() { return new MemoryStream(content); }
        public override void Close() { }
    }
}
