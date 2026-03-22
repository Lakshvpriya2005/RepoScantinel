
import React, { useState } from 'react';
import { Mail, Send, Github, Linkedin, MessageSquare, User } from 'lucide-react';

const Contact: React.FC = () => {
  const [sent, setSent] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSent(true);
    setTimeout(() => setSent(false), 5000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-20">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-20 items-center">
        <div>
          <h1 className="text-6xl font-black text-white mb-6">Let's Connect</h1>
          <p className="text-xl text-gray-400 mb-12 leading-relaxed">
            Feel free to reach out for collaboration or queries regarding repository security analysis.
          </p>

          <div className="space-y-8 mb-12">
            <div className="flex items-center space-x-6 p-6 glass-card rounded-3xl border border-white/10">
              <div className="w-14 h-14 bg-cyan-500/20 rounded-2xl flex items-center justify-center">
                <Mail className="w-6 h-6 text-cyan-400" />
              </div>
              <div>
                <h4 className="text-gray-400 text-sm font-bold uppercase tracking-wider">Contact Email</h4>
                <p className="text-lg text-white font-medium">lakshvpriya@gmail.com</p>
              </div>
            </div>

            <div className="flex items-center space-x-6 p-6 glass-card rounded-3xl border border-white/10">
              <div className="w-14 h-14 bg-purple-500/20 rounded-2xl flex items-center justify-center">
                <User className="w-6 h-6 text-purple-400" />
              </div>
              <div>
                <h4 className="text-gray-400 text-sm font-bold uppercase tracking-wider">Handler</h4>
                <p className="text-lg text-white font-medium">Lakshmipriya V</p>
              </div>
            </div>
          </div>

          <div className="flex space-x-4">
            <a
              href="https://github.com/Lakshvpriya2005"
              target="_blank"
              rel="noopener noreferrer"
              className="p-4 glass-card rounded-2xl border border-white/10 hover:bg-white/10 transition-all"
            >
              <Github className="w-6 h-6 text-white" />
            </a>
            <a
              href="https://www.linkedin.com/in/lakshmipriya3/"
              target="_blank"
              rel="noopener noreferrer"
              className="p-4 glass-card rounded-2xl border border-white/10 hover:bg-white/10 transition-all text-cyan-400"
            >
              <Linkedin className="w-6 h-6" />
            </a>
          </div>
        </div>

        <div className="glass-card p-10 rounded-[3rem] border border-white/10 relative">
          <div className="absolute -top-10 -right-10 w-40 h-40 bg-pink-500/10 blur-3xl rounded-full"></div>

          <h3 className="text-2xl font-bold text-white mb-8">Send a Message</h3>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <label className="text-sm font-bold text-gray-400 ml-4">Full Name</label>
              <input
                type="text"
                placeholder="John Doe"
                className="w-full px-6 py-4 rounded-2xl glass-card border-white/10 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-all"
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-bold text-gray-400 ml-4">Email Address</label>
              <input
                type="email"
                placeholder="john@example.com"
                className="w-full px-6 py-4 rounded-2xl glass-card border-white/10 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-all"
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-bold text-gray-400 ml-4">Your Message</label>
              <textarea
                rows={4}
                placeholder="I have a question about the scanning algorithm..."
                className="w-full px-6 py-4 rounded-2xl glass-card border-white/10 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-all resize-none"
                required
              ></textarea>
            </div>
            <button
              type="submit"
              className="w-full py-4 bg-gradient-to-r from-cyan-500 to-purple-500 text-white font-bold rounded-2xl hover:opacity-90 transition-all flex items-center justify-center group"
            >
              {sent ? "Message Received!" : "Send Message"}
              <Send className={`ml-2 w-5 h-5 group-hover:translate-x-1 group-hover:-translate-y-1 transition-transform ${sent ? 'hidden' : ''}`} />
            </button>
          </form>

          {sent && (
            <div className="mt-4 p-4 bg-green-500/10 border border-green-500/20 rounded-xl text-green-400 text-center animate-in fade-in slide-in-from-bottom-2 duration-500">
              Thank you for your message! We'll get back to you soon.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Contact;
