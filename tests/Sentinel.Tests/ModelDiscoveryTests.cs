using System.Net;
using System.Text.Json;
using Sentinel.Core;

internal static class ModelDiscoveryTests
{
    private static void Check(bool ok) { if (!ok) throw new Exception("Model discovery assertion failed"); }
    private static async Task Fails<T>(Func<Task> action) where T : Exception { try{await action();}catch(T){return;}throw new Exception("Expected "+typeof(T).Name); }
    public static void Register(Action<string,Func<Task>> test)
    {
        foreach(var provider in new[]{ProviderKind.OpenAiCompatible,ProviderKind.Ollama,ProviderKind.Anthropic})
        {
            var kind=provider;
            test("Model discovery uses metadata GET only: "+kind,async()=>{
                using var http=new HttpClient(new FakeHttp(request=>{
                    Check(request.Method==HttpMethod.Get && request.Content is null);
                    var expected=kind==ProviderKind.OpenAiCompatible?"/v1/models":kind==ProviderKind.Anthropic?"/v1/models":"/api/tags";
                    Check(request.RequestUri!.AbsolutePath==expected);
                    if(kind==ProviderKind.Anthropic){Check(request.Headers.GetValues("x-api-key").Single()=="fixture-key");Check(request.RequestUri.Query=="?limit=1000");}
                    else Check(request.Headers.Authorization?.Parameter=="fixture-key");
                    var json=kind==ProviderKind.Ollama?"{\"models\":[{\"name\":\"fixture:latest\"},{\"name\":\"fixture:latest\"}]}":"{\"data\":[{\"id\":\"fixture-model\"},{\"id\":\"fixture-model\"}]}";
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(json)});
                }));
                var result=await new AiModelDiscovery(http).ListAsync(kind,kind==ProviderKind.OpenAiCompatible?"https://example.com/v1/":"https://example.com/","fixture-key");
                Check(result.Models.Count==1 && !result.Truncated);
            });
        }
        test("Local Ollama discovery needs no credentials or model inference",async()=>{
            using var http=new HttpClient(new FakeHttp(request=>{Check(request.Headers.Authorization is null && request.RequestUri!.IsLoopback);return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("{\"models\":[]}")});}));
            Check((await new AiModelDiscovery(http).ListAsync(ProviderKind.Ollama,"http://127.0.0.1:11434/","")).Models.Count==0);
        });
        test("Discovery rejects invalid endpoints, keys and Codex before HTTP",async()=>{
            var calls=0;using var http=new HttpClient(new FakeHttp(_=>{calls++;throw new Exception("must not send");}));var client=new AiModelDiscovery(http);
            await Fails<ArgumentException>(()=>client.ListAsync(ProviderKind.OpenAiCompatible,"http://remote.example/","fixture"));
            await Fails<ArgumentException>(()=>client.ListAsync(ProviderKind.OpenAiCompatible,"https://example.com/",""));
            await Fails<ArgumentException>(()=>client.ListAsync(ProviderKind.Ollama,"http://localhost/","bad\nkey"));
            await Fails<NotSupportedException>(()=>client.ListAsync(ProviderKind.CodexAppServer,"", ""));Check(calls==0);
        });
        test("Discovery errors and redirects do not echo provider bodies",async()=>{
            foreach(var status in new[]{HttpStatusCode.Unauthorized,HttpStatusCode.Redirect})
            {
                using var http=new HttpClient(new FakeHttp(_=>Task.FromResult(new HttpResponseMessage(status){Content=new StringContent("private-key echoed body")})));
                try{await new AiModelDiscovery(http).ListAsync(ProviderKind.Ollama,"http://localhost/","");throw new Exception("expected failure");}
                catch(InvalidOperationException ex){Check(!ex.Message.Contains("private-key"));}
            }
        });
        test("Discovery rejects oversized, malformed and unsafe model metadata",async()=>{
            foreach(var json in new[]{new string('x',AiModelDiscovery.MaxBytes+1),"[]","{}","{\"models\":[{\"name\":\"bad\\nmodel\"}]}","{\"models\":[{\"name\":null}]}"})
            {
                using var http=new HttpClient(new FakeHttp(_=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(json)})));
                await Fails<InvalidDataException>(()=>new AiModelDiscovery(http).ListAsync(ProviderKind.Ollama,"http://localhost/",""));
            }
        });
        test("Discovery caps returned models and exposes provider pagination",async()=>{
            var json=JsonSerializer.Serialize(new{data=Enumerable.Range(0,1001).Select(i=>new{id=$"fixture-{i:0000}"}),has_more=true});
            using var http=new HttpClient(new FakeHttp(_=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(json)})));
            var result=await new AiModelDiscovery(http).ListAsync(ProviderKind.Anthropic,"http://localhost/","");Check(result.Models.Count==1000 && result.Truncated);
        });
        test("Discovery propagates cancellation",async()=>{
            using var http=new HttpClient(new FakeHttp(_=>throw new OperationCanceledException()));
            await Fails<OperationCanceledException>(()=>new AiModelDiscovery(http).ListAsync(ProviderKind.Ollama,"http://localhost/",""));
        });
    }
}
